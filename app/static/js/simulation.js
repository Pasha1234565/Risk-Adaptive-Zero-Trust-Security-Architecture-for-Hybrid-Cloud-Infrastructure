/* Attack scenario runner. Every request stays inside the local process. */
(function () {
  "use strict";

  const state = { scenarios: [], total: 0, detected: 0, maxRisk: 0, latencies: [] };

  function scenarioCard(scenario) {
    return (
      '<article class="scenario-card" data-scenario="' + window.ZT.escape(scenario.id) + '">' +
        '<div class="scenario-top"><h3>' + window.ZT.escape(scenario.name) + "</h3>" +
          '<span class="severity-tag ' + window.ZT.escape(scenario.severity) + '">' + window.ZT.escape(scenario.severity) + "</span></div>" +
        '<span class="technique">' + window.ZT.escape(scenario.technique) + "</span>" +
        '<p class="scenario-desc">' + window.ZT.escape(scenario.description) + "</p>" +
        '<div class="scenario-meta">' +
          "<span>" + window.ZT.escape(scenario.user_email) + "</span>" +
          "<span class=\"mono\">→ " + window.ZT.escape(scenario.resource) + "</span>" +
          "<span>" + window.ZT.escape(scenario.context.geo) + " · " + window.ZT.escape(scenario.context.hour) + ":00</span>" +
        "</div>" +
        '<div class="scenario-foot">' +
          '<span class="chip">Ground truth: attack</span>' +
          '<button class="btn btn-ghost small" data-run="' + window.ZT.escape(scenario.id) + '">Run scenario</button>' +
        "</div>" +
      "</article>"
    );
  }

  function updateSummary() {
    document.getElementById("sim-total").textContent = state.total;
    document.getElementById("sim-detected").textContent = state.detected;
    document.getElementById("sim-maxrisk").textContent = state.maxRisk ? state.maxRisk.toFixed(0) + " / 100" : "—";
    document.getElementById("sim-latency").textContent = state.latencies.length
      ? (state.latencies.reduce(function (sum, value) { return sum + value; }, 0) / state.latencies.length).toFixed(2) + " ms"
      : "—";
  }

  function renderResults(title, subtitle, results, expected) {
    const card = document.getElementById("sim-results");
    card.hidden = false;
    document.getElementById("sim-results-title").textContent = title;
    document.getElementById("sim-results-sub").textContent = subtitle;

    document.querySelector("#sim-table tbody").innerHTML = results.map(function (result) {
      return (
        "<tr>" +
          "<td><span class=\"strong\">" + window.ZT.escape(result.scenario_name || "Normal traffic") + "</span>" +
            '<div class="zone-tag">' + window.ZT.escape(result.context.note || "") + "</div></td>" +
          '<td><span class="mono">' + window.ZT.escape(result.technique || "Baseline") + "</span></td>" +
          "<td>" + window.ZT.escape(result.user.name) + ' <span class="zone-tag">→</span> ' +
            window.ZT.escape(result.resource.name) + "</td>" +
          '<td><span class="mono">' + Number(result.anomaly_score).toFixed(2) + "</span></td>" +
          "<td>" + window.ZT.riskPill(result.risk_score) + "</td>" +
          "<td>" + window.ZT.decisionBadge(result.decision) + "</td>" +
          '<td><span class="chip">' + (expected === "attack" ? "Attack" : "Normal") + "</span></td>" +
        "</tr>"
      );
    }).join("");

    results.forEach(function (result) {
      state.total += 1;
      if (result.decision !== "ALLOW") state.detected += 1;
      state.maxRisk = Math.max(state.maxRisk, Number(result.risk_score));
      state.latencies.push(Number(result.latency_ms));
    });
    updateSummary();
    card.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function runScenario(scenarioId, button) {
    window.ZT.setLoading(button, true, "Running…");
    try {
      const variants = Number(document.getElementById("variant-count").value) || 3;
      const data = await window.ZT.api("/api/sim/scenario", {
        method: "POST",
        body: { scenario_id: scenarioId, variants: variants },
      });
      const scenario = state.scenarios.find(function (item) { return item.id === scenarioId; });
      renderResults(
        scenario ? scenario.name : data.scenario,
        variants + " labelled variants evaluated · " + data.summary.detected + " elevated",
        data.results,
        "attack"
      );
      window.ZT.toast(data.scenario + " complete: " + data.summary.detected + "/" + data.summary.total + " elevated.", "ok");
      window.ZT.refreshAlertBadge();
    } catch (err) {
      window.ZT.toast(err.message, "error");
    } finally {
      window.ZT.setLoading(button, false);
    }
  }

  async function runNormal() {
    const button = document.getElementById("run-normal");
    window.ZT.setLoading(button, true, "Running…");
    try {
      const count = Number(document.getElementById("normal-count").value) || 25;
      const data = await window.ZT.api("/api/sim/normal", { method: "POST", body: { count: count } });
      renderResults(
        "Normal traffic baseline",
        count + " legitimate sessions · " + data.summary.detected + " elevated",
        data.results,
        "normal"
      );
      window.ZT.toast("Generated " + count + " normal sessions.", "ok");
    } catch (err) {
      window.ZT.toast(err.message, "error");
    } finally {
      window.ZT.setLoading(button, false);
    }
  }

  async function runFullEvaluation() {
    const button = document.getElementById("run-full-eval");
    window.ZT.setLoading(button, true, "Evaluating…");
    try {
      const data = await window.ZT.api("/api/sim/evaluation", {
        method: "POST",
        body: { name: "Simulation-lab evaluation", normal_samples: 140, variants: 3 },
      });
      window.ZT.toast(
        "Evaluation complete · accuracy " + window.ZT.fmtPct(data.detection.accuracy) +
        " · FPR " + window.ZT.fmtPct(data.detection.false_positive_rate),
        "ok"
      );
      window.location.href = "/evaluation?run=" + data.run_id;
    } catch (err) {
      window.ZT.toast(err.message, "error");
      window.ZT.setLoading(button, false);
    }
  }

  async function init() {
    try {
      const data = await window.ZT.api("/api/sim/scenarios");
      state.scenarios = data.scenarios;
      document.getElementById("scenario-count").textContent = data.scenarios.length + " scenarios";
      document.getElementById("scenario-grid").innerHTML = data.scenarios.map(scenarioCard).join("");
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }

    document.getElementById("scenario-grid").addEventListener("click", function (event) {
      const button = event.target.closest("[data-run]");
      if (button) runScenario(button.dataset.run, button);
    });
    document.getElementById("run-normal").addEventListener("click", runNormal);
    document.getElementById("run-full-eval").addEventListener("click", runFullEvaluation);
    updateSummary();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
