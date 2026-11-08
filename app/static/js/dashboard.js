/* Trust overview page. */
(function () {
  "use strict";

  function kpi(label, value, foot, tone, unit) {
    return (
      '<div class="kpi ' + (tone || "") + '">' +
        '<div class="kpi-label">' + window.ZT.escape(label) + "</div>" +
        '<div class="kpi-value">' + value + (unit ? "<small>" + window.ZT.escape(unit) + "</small>" : "") + "</div>" +
        '<div class="kpi-foot">' + window.ZT.escape(foot) + "</div>" +
      "</div>"
    );
  }

  function render(data) {
    const stats = data.stats;
    const total = stats.events_24h || 0;
    const allowPct = total ? (stats.allowed / total) * 100 : 0;
    const elevated = stats.challenged + stats.restricted + stats.blocked;
    const accuracy = stats.detection_accuracy;
    const fpr = stats.false_positive_rate;

    document.getElementById("kpi-grid").innerHTML = [
      kpi("Events evaluated", window.ZT.int(total), "Across both trust zones · last 24 h", "accent"),
      kpi("Elevated responses", window.ZT.int(elevated), allowPct.toFixed(0) + "% allowed", elevated ? "warn" : "ok"),
      kpi("Open alerts", window.ZT.int(stats.open_alerts), "Restrict / block triage queue", stats.open_alerts ? "danger" : "ok"),
      kpi("Average risk", Number(stats.avg_risk).toFixed(1), "Weighted contextual score", Number(stats.avg_risk) >= 60 ? "warn" : ""),
      kpi("Decision latency", Number(stats.avg_latency_ms).toFixed(2), "Average PDP evaluation", ""),
      kpi("Detection accuracy", accuracy === null || accuracy === undefined ? "—" : (accuracy * 100).toFixed(1) + "%",
        fpr === null || fpr === undefined ? "Awaiting evaluation" : "FPR " + (fpr * 100).toFixed(1) + "%", ""),
    ].join("");

    window.Charts.barChart(
      document.getElementById("risk-bars"),
      [
        { label: "0–19", count: data.risk_bins[0].count, color: "allow" },
        { label: "20–39", count: data.risk_bins[1].count, color: "allow" },
        { label: "40–59", count: data.risk_bins[2].count, color: "challenge" },
        { label: "60–79", count: data.risk_bins[3].count, color: "restrict" },
        { label: "80–100", count: data.risk_bins[4].count, color: "block" },
      ],
      { flat: true }
    );

    const decisions = data.decisions;
    const mapped = decisions.map(function (item) {
      return {
        label: item.decision,
        value: item.count,
        color: window.Charts.COLORS[item.decision] || "#64748b",
      };
    });
    window.Charts.donut(document.getElementById("decision-donut"), mapped, {
      centerValue: window.ZT.int(total),
      centerLabel: "evaluated",
    });
    document.getElementById("decision-legend").innerHTML = mapped.map(function (item) {
      return (
        '<div class="row"><span><i class="swatch ' + item.label.toLowerCase() + '"></i>' +
        window.ZT.escape(window.ZT.decisionMeta(item.label).label) + "</span>" +
        "<strong>" + item.value + "</strong></div>"
      );
    }).join("");

    const alertList = document.getElementById("alert-list");
    if (!data.alerts.length) {
      alertList.innerHTML =
        '<div class="alert-empty">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M12 3 5 6v6c0 4.4 3 8.2 7 9.4 4-1.2 7-5 7-9.4V6l-7-3Z"/><path d="m9 12 2 2 4-4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
          "No open alerts. Containment decisions will appear here." +
        "</div>";
    } else {
      alertList.innerHTML = data.alerts.map(function (alert) {
        return (
          '<a class="alert-item ' + window.ZT.escape(alert.severity) + '" href="/monitoring?event=' + alert.id + '">' +
            '<span class="alert-sev ' + window.ZT.escape(alert.severity) + '"></span>' +
            '<span class="alert-body">' +
              '<span class="alert-title">' + window.ZT.escape(alert.title) + "</span>" +
              '<span class="alert-detail">' + window.ZT.escape(alert.detail) + "</span>" +
              '<span class="alert-meta"><span>' + window.ZT.escape(alert.severity) + " severity</span><span>" +
                window.ZT.timeAgo(alert.ts) + "</span></span>" +
            "</span>" +
          "</a>"
        );
      }).join("");
    }

    document.getElementById("model-meta").innerHTML = [
      ["Algorithm", data.model.algorithm],
      ["Baseline samples", window.ZT.int(data.model.samples)],
      ["Anomaly threshold", Number(data.model.threshold).toFixed(3)],
      ["Last trained", window.ZT.timeAgo(data.model.trained_at)],
    ].map(function (pair) {
      return "<div><dt>" + window.ZT.escape(pair[0]) + "</dt><dd>" + window.ZT.escape(pair[1]) + "</dd></div>";
    }).join("");

    const tbody = document.querySelector("#recent-table tbody");
    if (!data.recent.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty compact">No events yet.</td></tr>';
    } else {
      tbody.innerHTML = data.recent.map(function (event) {
        return (
          "<tr>" +
            '<td class="nowrap" title="' + window.ZT.escape(event.ts) + '">' + window.ZT.timeAgo(event.ts) + "</td>" +
            '<td class="strong">' + window.ZT.escape(event.user_name || "Unknown") + "</td>" +
            '<td>' + window.ZT.escape(event.resource_name || "—") +
              ' <span class="zone-tag">' + window.ZT.escape(event.resource_zone || "") + "</span></td>" +
            "<td>" + window.ZT.escape(event.device_name || "—") + "</td>" +
            "<td>" + window.ZT.riskPill(event.risk_score) + "</td>" +
            "<td>" + window.ZT.decisionBadge(event.decision) + "</td>" +
            '<td><a class="arrow-link" href="/monitoring?event=' + event.id + '" aria-label="Open event">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 6l6 6-6 6"/></svg></a></td>' +
          "</tr>"
        );
      }).join("");
    }

    document.getElementById("updated-at").textContent = "Updated " + new Date().toLocaleTimeString();
  }

  function renderEstate(topology) {
    const privateBox = document.getElementById("private-nodes");
    const publicBox = document.getElementById("public-nodes");
    if (!privateBox || !publicBox) return;
    function chips(items) {
      const visible = items.slice(0, 7);
      return visible.map(function (item) {
        return '<span class="node-chip ' + window.ZT.escape(item.sensitivity) + '" title="' +
          window.ZT.escape(item.service + " · " + item.category) + '">' +
          window.ZT.escape(item.name) + "</span>";
      }).join("") + (items.length > visible.length
        ? '<span class="node-chip">+' + (items.length - visible.length) + " more</span>"
        : "");
    }
    privateBox.innerHTML = chips(topology.zones.private);
    publicBox.innerHTML = chips(topology.zones.public);
  }

  async function init() {
    try {
      const results = await Promise.all([
        window.ZT.api("/api/dashboard"),
        window.ZT.api("/api/topology"),
      ]);
      render(results[0]);
      renderEstate(results[1]);
    } catch (err) {
      window.ZT.toast(err.message, "error");
      document.getElementById("kpi-grid").innerHTML =
        '<div class="empty" style="grid-column:1/-1">Unable to load telemetry: ' + window.ZT.escape(err.message) + "</div>";
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
