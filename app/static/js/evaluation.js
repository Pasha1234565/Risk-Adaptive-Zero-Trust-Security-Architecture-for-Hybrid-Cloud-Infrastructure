/* Evaluation dashboard: metrics, confusion matrix, latency and history. */
(function () {
  "use strict";

  const state = { runs: [], currentId: null };

  function kpi(label, value, foot, tone) {
    return '<div class="kpi ' + (tone || "") + '"><div class="kpi-label">' + window.ZT.escape(label) +
      '</div><div class="kpi-value">' + value + '</div><div class="kpi-foot">' +
      window.ZT.escape(foot) + "</div></div>";
  }

  function renderMetrics(metrics) {
    state.currentId = metrics.run_id || null;
    const detection = metrics.detection || {};
    const anomaly = metrics.anomaly_detection || {};
    const latency = metrics.latency || {};
    const availability = metrics.availability || {};
    const samples = metrics.samples || {};

    document.getElementById("eval-kpis").innerHTML = [
      kpi("Detection accuracy", window.ZT.fmtPct(detection.accuracy), "Challenge + Restrict + Block count as detected",
        (detection.accuracy || 0) >= 0.9 ? "ok" : "warn"),
      kpi("False positive rate", window.ZT.fmtPct(detection.false_positive_rate), "Legitimate sessions elevated",
        (detection.false_positive_rate || 0) <= 0.08 ? "ok" : "warn"),
      kpi("False negative rate", window.ZT.fmtPct(detection.false_negative_rate), "Attacks allowed through",
        (detection.false_negative_rate || 0) <= 0.05 ? "ok" : "danger"),
      kpi("Decision p95", Number(latency.decision_p95_ms || 0).toFixed(2), "Milliseconds inside the PDP", ""),
      kpi("Auth overhead", Number(latency.auth_overhead_ms || 0).toFixed(1), "PBKDF2-SHA256 verification", ""),
      kpi("Availability", Number(availability.rate || 0).toFixed(2) + "%",
        (availability.engine_errors || 0) + " engine error(s)", "ok"),
    ].join("");

    document.getElementById("eval-samples").textContent =
      window.ZT.int(samples.total) + " samples · " + window.ZT.int(samples.attack) + " attack";
    document.getElementById("eval-updated").textContent =
      (metrics.name || "Evaluation") + " · " + window.ZT.fmtTime(metrics.generated_at);

    document.getElementById("confusion-matrix").innerHTML =
      '<div class="confusion">' +
        "<div></div>" +
        '<div class="confusion-head">Predicted elevated</div>' +
        '<div class="confusion-head">Predicted allow</div>' +
        '<div class="confusion-label">Actual normal</div>' +
        '<div class="confusion-cell fp"><strong>' + window.ZT.int(detection.fp) + "</strong><span>false positive</span></div>" +
        '<div class="confusion-cell tn"><strong>' + window.ZT.int(detection.tn) + "</strong><span>true negative</span></div>" +
        '<div class="confusion-label">Actual attack</div>' +
        '<div class="confusion-cell tp"><strong>' + window.ZT.int(detection.tp) + "</strong><span>true positive</span></div>" +
        '<div class="confusion-cell fn"><strong>' + window.ZT.int(detection.fn) + "</strong><span>false negative</span></div>" +
      "</div>";

    document.getElementById("detection-extra").innerHTML = [
      ["Precision", window.ZT.fmtPct(detection.precision)],
      ["Recall", window.ZT.fmtPct(detection.recall)],
      ["F1 score", Number(detection.f1 || 0).toFixed(3)],
      ["Evaluated", window.ZT.int(detection.total)],
    ].map(function (pair) {
      return "<div><dt>" + window.ZT.escape(pair[0]) + "</dt><dd>" + window.ZT.escape(pair[1]) + "</dd></div>";
    }).join("");

    window.Charts.barChart(
      document.getElementById("latency-chart"),
      [
        { label: "Decision", count: latency.decision_avg_ms, color: "accent" },
        { label: "p95", count: latency.decision_p95_ms, color: "challenge" },
        { label: "Auth", count: latency.auth_overhead_ms, color: "restrict" },
        { label: "Service", count: latency.service_latency_ms, color: "allow" },
      ],
      { format: function (value) { return Number(value).toFixed(1); } }
    );

    document.getElementById("latency-list").innerHTML = [
      ["Decision average", latency.decision_avg_ms],
      ["Decision median", latency.decision_p50_ms],
      ["Decision maximum", latency.decision_max_ms],
      ["Authentication overhead", latency.auth_overhead_ms],
      ["Protected-service read", latency.service_latency_ms],
    ].map(function (pair) {
      return '<div class="latency-item"><span>' + window.ZT.escape(pair[0]) +
        "</span><strong>" + Number(pair[1] || 0).toFixed(2) + " ms</strong></div>";
    }).join("");

    const rows = metrics.per_scenario || [];
    document.querySelector("#scenario-eval-table tbody").innerHTML = rows.map(function (row) {
      const result = row.contained ? "Contained" : row.detected ? "Detected" : "Missed";
      return (
        "<tr>" +
          '<td><span class="strong">' + window.ZT.escape(row.name) + "</span>" +
            '<div class="zone-tag">' + window.ZT.escape(row.technique) + "</div></td>" +
          "<td>" + window.ZT.riskPill(row.risk_score) + "</td>" +
          '<td><span class="mono">' + Number(row.anomaly_score).toFixed(2) + "</span></td>" +
          "<td>" + window.ZT.decisionBadge(row.decision) + "</td>" +
          '<td><span class="chip">' + result + "</span></td>" +
        "</tr>"
      );
    }).join("") || '<tr><td colspan="5" class="empty compact">No per-scenario data in this run.</td></tr>';

    document.getElementById("eval-model-meta").innerHTML = [
      ["Algorithm", (metrics.model || {}).algorithm || "—"],
      ["Baseline samples", window.ZT.int((metrics.model || {}).baseline_samples)],
      ["Anomaly threshold", Number((metrics.model || {}).threshold || 0).toFixed(3)],
      ["Run duration", Number(metrics.duration_ms || 0).toFixed(0) + " ms"],
      ["Model trained", window.ZT.timeAgo((metrics.model || {}).trained_at)],
      ["Run ID", metrics.run_id ? "#" + metrics.run_id : "unsaved"],
    ].map(function (pair) {
      return "<div><dt>" + window.ZT.escape(pair[0]) + "</dt><dd>" + window.ZT.escape(pair[1]) + "</dd></div>";
    }).join("");

    document.getElementById("availability-value").textContent = Number(availability.rate || 0).toFixed(2) + "%";
    document.getElementById("availability-bar").style.width = Math.max(0, Math.min(100, Number(availability.rate || 0))) + "%";
    document.getElementById("availability-detail").textContent =
      window.ZT.int(availability.successful) + " of " + window.ZT.int(availability.total) +
      " evaluation requests produced a decision without an engine error.";

    document.getElementById("anomaly-metrics").innerHTML = [
      ["Anomaly accuracy", window.ZT.fmtPct(anomaly.accuracy)],
      ["Anomaly FPR", window.ZT.fmtPct(anomaly.false_positive_rate)],
      ["Anomaly FNR", window.ZT.fmtPct(anomaly.false_negative_rate)],
    ].map(function (pair) {
      return "<div><span>" + window.ZT.escape(pair[0]) + "</span><strong>" + window.ZT.escape(pair[1]) + "</strong></div>";
    }).join("");
  }

  function renderHistory() {
    const tbody = document.querySelector("#history-table tbody");
    if (!state.runs.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty compact">No stored runs yet.</td></tr>';
      return;
    }
    tbody.innerHTML = state.runs.map(function (run) {
      return (
        '<tr data-run="' + run.id + '">' +
          '<td class="strong">#' + run.id + ' · ' + window.ZT.escape(run.name) + "</td>" +
          '<td class="nowrap">' + window.ZT.fmtTime(run.ts) + "</td>" +
          "<td>" + window.ZT.int(run.samples) + "</td>" +
          "<td>" + window.ZT.fmtPct(run.accuracy) + "</td>" +
          "<td>" + window.ZT.fmtPct(run.false_positive_rate) + "</td>" +
          "<td>" + window.ZT.fmtPct(run.false_negative_rate) + "</td>" +
          '<td class="mono">' + Number(run.duration_ms || 0).toFixed(0) + " ms</td>" +
        "</tr>"
      );
    }).join("");
  }

  async function loadHistory() {
    try {
      const data = await window.ZT.api("/api/evaluation/runs?limit=20");
      state.runs = data.runs;
      renderHistory();
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }
  }

  async function loadRun(runId) {
    try {
      const metrics = await window.ZT.api("/api/evaluation/runs/" + runId);
      renderMetrics(metrics);
      const url = new URL(window.location.href);
      url.searchParams.set("run", String(runId));
      window.history.replaceState({}, "", url);
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }
  }

  async function runEvaluation() {
    const button = document.getElementById("run-evaluation");
    window.ZT.setLoading(button, true, "Evaluating…");
    try {
      const metrics = await window.ZT.api("/api/sim/evaluation", {
        method: "POST",
        body: { name: "Manual console evaluation", normal_samples: 140, variants: 3 },
      });
      renderMetrics(metrics);
      await loadHistory();
      const url = new URL(window.location.href);
      url.searchParams.set("run", String(metrics.run_id));
      window.history.replaceState({}, "", url);
      window.ZT.toast("Evaluation complete and stored as run #" + metrics.run_id + ".", "ok");
    } catch (err) {
      window.ZT.toast(err.message, "error");
    } finally {
      window.ZT.setLoading(button, false);
    }
  }

  async function init() {
    await loadHistory();
    const params = new URLSearchParams(window.location.search);
    const requested = params.get("run");
    if (requested) {
      await loadRun(requested);
    } else if (state.runs.length) {
      await loadRun(state.runs[0].id);
    }

    document.getElementById("run-evaluation").addEventListener("click", runEvaluation);
    document.getElementById("refresh-history").addEventListener("click", async function () {
      await loadHistory();
      window.ZT.toast("Evaluation history refreshed.", "ok");
    });
    document.querySelector("#history-table tbody").addEventListener("click", function (event) {
      const row = event.target.closest("tr[data-run]");
      if (row) loadRun(row.dataset.run);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
