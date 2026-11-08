/* Security event log and alert triage. */
(function () {
  "use strict";

  const state = { limit: 25, offset: 0, total: 0, events: [], filtersLoaded: false };

  function filters() {
    return {
      decision: document.getElementById("filter-decision").value,
      truth: document.getElementById("filter-truth").value,
      scenario: document.getElementById("filter-scenario").value,
      user_id: document.getElementById("filter-user").value,
    };
  }

  function renderKpis(stats) {
    document.getElementById("monitor-kpis").innerHTML = [
      { label: "Events · 24 h", value: window.ZT.int(stats.events_24h), foot: "All trust zones", tone: "accent" },
      { label: "Allowed", value: window.ZT.int(stats.allowed), foot: "Least-privilege sessions", tone: "ok" },
      { label: "Elevated", value: window.ZT.int(stats.challenged + stats.restricted + stats.blocked), foot: "Challenge / restrict / block", tone: "warn" },
      { label: "Open alerts", value: window.ZT.int(stats.open_alerts), foot: "Awaiting triage", tone: stats.open_alerts ? "danger" : "ok" },
    ].map(function (item) {
      return '<div class="kpi ' + item.tone + '"><div class="kpi-label">' + window.ZT.escape(item.label) +
        '</div><div class="kpi-value">' + item.value + '</div><div class="kpi-foot">' +
        window.ZT.escape(item.foot) + "</div></div>";
    }).join("");
  }

  async function loadStats() {
    try {
      const data = await window.ZT.api("/api/dashboard");
      renderKpis(data.stats);
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }
  }

  function eventQuery() {
    const f = filters();
    const params = new URLSearchParams();
    params.set("limit", String(state.limit));
    params.set("offset", String(state.offset));
    if (f.decision !== "ALL") params.set("decision", f.decision);
    if (f.truth !== "all") params.set("truth", f.truth);
    if (f.scenario !== "all") params.set("scenario", f.scenario);
    if (f.user_id) params.set("user_id", f.user_id);
    return params.toString();
  }

  async function loadEvents() {
    const tbody = document.querySelector("#events-table tbody");
    tbody.innerHTML = '<tr><td colspan="7" class="empty compact">Loading events…</td></tr>';
    try {
      const data = await window.ZT.api("/api/events?" + eventQuery());
      state.total = data.total;
      state.events = data.events;
      if (!data.events.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty compact">No events match these filters.</td></tr>';
      } else {
        tbody.innerHTML = data.events.map(function (event) {
          return (
            '<tr data-event-id="' + event.id + '">' +
              '<td class="nowrap" title="' + window.ZT.escape(event.ts) + '">' + window.ZT.timeAgo(event.ts) + "</td>" +
              '<td><span class="strong">' + window.ZT.escape(event.user_name || "Unknown") + "</span>" +
                '<div class="zone-tag">' + window.ZT.escape(event.user_role || "") + "</div></td>" +
              "<td>" + window.ZT.escape(event.resource_name || "—") + "</td>" +
              '<td><span class="zone-tag">' + window.ZT.escape(event.resource_zone || "—") + "</span></td>" +
              "<td>" + window.ZT.riskPill(event.risk_score) + "</td>" +
              '<td><span class="mono">' + Number(event.anomaly_score).toFixed(2) + "</span></td>" +
              "<td>" + window.ZT.decisionBadge(event.decision) + "</td>" +
            "</tr>"
          );
        }).join("");
      }
      const from = state.total ? state.offset + 1 : 0;
      const to = Math.min(state.offset + state.limit, state.total);
      document.getElementById("page-info").textContent =
        "Showing " + from + "–" + to + " of " + window.ZT.int(state.total) + " events";
      document.getElementById("event-count").textContent =
        window.ZT.int(data.total) + " matching decisions";
      document.getElementById("prev-page").disabled = state.offset <= 0;
      document.getElementById("next-page").disabled = state.offset + state.limit >= state.total;
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty compact">' + window.ZT.escape(err.message) + "</td></tr>";
    }
  }

  async function loadAlerts() {
    const panel = document.getElementById("alerts-panel");
    try {
      const data = await window.ZT.api("/api/alerts?status=open&limit=30");
      document.getElementById("alert-count").textContent = data.open_count;
      document.getElementById("alert-badge").hidden = data.open_count === 0;
      document.getElementById("alert-badge").textContent = data.open_count;
      if (!data.alerts.length) {
        panel.innerHTML =
          '<div class="alert-empty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M12 3 5 6v6c0 4.4 3 8.2 7 9.4 4-1.2 7-5 7-9.4V6l-7-3Z"/><path d="m9 12 2 2 4-4.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
          "No open alerts. Containment decisions appear here for triage.</div>";
        return;
      }
      panel.innerHTML = data.alerts.map(function (alert) {
        return (
          '<div class="alert-item ' + window.ZT.escape(alert.severity) + '">' +
            '<span class="alert-sev ' + window.ZT.escape(alert.severity) + '"></span>' +
            '<span class="alert-body">' +
              '<span class="alert-title" data-event="' + alert.event_id + '" style="cursor:pointer">' +
                window.ZT.escape(alert.title) + "</span>" +
              '<span class="alert-detail">' + window.ZT.escape(alert.detail) + "</span>" +
              '<span class="alert-meta"><span>' + window.ZT.escape(alert.user_name || "Unknown") + "</span>" +
                "<span>" + window.ZT.timeAgo(alert.ts) + "</span></span>" +
            "</span>" +
            '<span class="alert-actions"><button class="btn btn-ghost small" data-ack="' + alert.id + '">Ack</button></span>' +
          "</div>"
        );
      }).join("");
    } catch (err) {
      panel.innerHTML = '<div class="alert-empty">' + window.ZT.escape(err.message) + "</div>";
    }
  }

  function openEvent(eventId) {
    window.ZT.api("/api/events/" + eventId).then(function (event) {
      const meta = window.ZT.decisionMeta(event.decision);
      const signals = (event.signals || []).map(function (signal) {
        return '<div class="signal"><div class="signal-head"><span>' + window.ZT.escape(signal.label) +
          '</span><strong>' + Number(signal.points).toFixed(1) + "</strong></div>" +
          '<div class="signal-track"><div class="signal-fill" style="width:' +
          Math.round(Math.min(1, signal.factor) * 100) + '%"></div></div></div>';
      }).join("");
      const reasons = (event.reasons || []).map(function (reason) {
        return '<li class="reason"><span class="severity-dot ' + window.ZT.escape(reason.severity) + '"></span><span>' +
          window.ZT.escape(reason.text) + "</span></li>";
      }).join("");
      const detail = [
        ["Identity", event.user_name + " · " + event.user_email],
        ["Role", event.user_role],
        ["Device", event.device_name + " · trust " + event.device_trust],
        ["Resource", event.resource_name + " · " + event.resource_sensitivity],
        ["Zone", event.resource_zone],
        ["Scenario", event.scenario],
        ["Ground truth", event.ground_truth ? "Attack" : "Normal"],
        ["Source IP", event.source_ip],
        ["Geolocation", event.geo],
        ["Latency", Number(event.latency_ms).toFixed(2) + " ms"],
        ["Timestamp", window.ZT.fmtTime(event.ts)],
        ["Outcome", event.outcome],
      ].map(function (pair) {
        return '<div class="detail-row"><span>' + window.ZT.escape(pair[0]) + "</span><strong>" +
          window.ZT.escape(pair[1] || "—") + "</strong></div>";
      }).join("");

      window.ZT.openModal(
        "Access decision #" + event.id,
        event.user_name + " → " + event.resource_name,
        '<div class="detail-hero">' +
          "<div>" + window.ZT.decisionBadge(event.decision) +
            '<div class="muted" style="font-size:11px;margin-top:6px">' + window.ZT.escape(meta.summary) + "</div></div>" +
          '<div style="text-align:right"><div class="big-risk" style="color:var(--' +
            (event.decision === "BLOCK" ? "block" : event.decision === "RESTRICT" ? "restrict" : event.decision === "CHALLENGE" ? "challenge" : "allow") +
            ')">' + Number(event.risk_score).toFixed(0) + '</div><div class="zone-tag">risk / 100</div></div>' +
        "</div>" +
        '<div class="detail-grid">' + detail + "</div>" +
        '<div class="detail-section"><h3>Reasons</h3><ul class="reason-list">' + reasons + "</ul></div>" +
        '<div class="detail-section"><h3>Signal contribution</h3><div class="signal-list">' + signals + "</div></div>" +
        '<div class="detail-section"><h3>Request context</h3><pre class="json-pre">' +
          window.ZT.escape(JSON.stringify(event.context, null, 2)) + "</pre></div>"
      );
    }).catch(function (err) {
      window.ZT.toast(err.message, "error");
    });
  }

  function csvEscape(value) {
    const text = value === null || value === undefined ? "" : String(value);
    return '"' + text.replace(/"/g, '""') + '"';
  }

  function exportCsv() {
    if (!state.events.length) {
      window.ZT.toast("No events loaded to export.", "warn");
      return;
    }
    const headers = ["id", "ts", "user", "role", "device", "resource", "zone", "sensitivity", "decision",
      "risk_score", "anomaly_score", "scenario", "ground_truth", "source_ip", "geo", "latency_ms"];
    const lines = [headers.join(",")].concat(state.events.map(function (event) {
      return [
        event.id, event.ts, event.user_name, event.user_role, event.device_name, event.resource_name,
        event.resource_zone, event.resource_sensitivity, event.decision, event.risk_score,
        event.anomaly_score, event.scenario, event.ground_truth ? "attack" : "normal",
        event.source_ip, event.geo, event.latency_ms,
      ].map(csvEscape).join(",");
    }));
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "zero-trust-events-" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    window.ZT.toast("Exported " + state.events.length + " events.", "ok");
  }

  async function initFilters() {
    if (state.filtersLoaded) return;
    try {
      const results = await Promise.all([
        window.ZT.api("/api/context/inventory"),
        window.ZT.api("/api/sim/scenarios"),
      ]);
      const users = results[0].users;
      const scenarios = results[1].scenarios;
      document.getElementById("filter-user").innerHTML =
        '<option value="">All identities</option>' +
        users.map(function (user) {
          return '<option value="' + user.id + '">' + window.ZT.escape(user.name) + "</option>";
        }).join("");
      document.getElementById("filter-scenario").innerHTML =
        '<option value="all">All scenarios</option><option value="normal">Normal baseline</option>' +
        scenarios.map(function (scenario) {
          return '<option value="' + window.ZT.escape(scenario.id) + '">' + window.ZT.escape(scenario.name) + "</option>";
        }).join("");
      state.filtersLoaded = true;
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }
  }

  async function refreshAll() {
    await Promise.all([loadEvents(), loadAlerts(), loadStats()]);
  }

  function resetFilters() {
    document.getElementById("filter-decision").value = "ALL";
    document.getElementById("filter-truth").value = "all";
    document.getElementById("filter-scenario").value = "all";
    document.getElementById("filter-user").value = "";
    state.offset = 0;
    loadEvents();
  }

  async function init() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("truth")) document.getElementById("filter-truth").value = params.get("truth");
    if (params.get("scenario")) document.getElementById("filter-scenario").value = params.get("scenario");

    await initFilters();
    if (params.get("truth")) document.getElementById("filter-truth").value = params.get("truth");
    if (params.get("scenario")) document.getElementById("filter-scenario").value = params.get("scenario");

    ["filter-decision", "filter-truth", "filter-scenario", "filter-user"].forEach(function (id) {
      document.getElementById(id).addEventListener("change", function () {
        state.offset = 0;
        loadEvents();
      });
    });
    document.getElementById("reset-filters").addEventListener("click", resetFilters);
    document.getElementById("refresh-monitoring").addEventListener("click", refreshAll);
    document.getElementById("export-csv").addEventListener("click", exportCsv);
    document.getElementById("prev-page").addEventListener("click", function () {
      state.offset = Math.max(0, state.offset - state.limit);
      loadEvents();
    });
    document.getElementById("next-page").addEventListener("click", function () {
      if (state.offset + state.limit < state.total) {
        state.offset += state.limit;
        loadEvents();
      }
    });
    document.querySelector("#events-table tbody").addEventListener("click", function (event) {
      const row = event.target.closest("tr[data-event-id]");
      if (row) openEvent(row.dataset.eventId);
    });
    document.getElementById("alerts-panel").addEventListener("click", async function (event) {
      const ack = event.target.closest("[data-ack]");
      if (ack) {
        event.stopPropagation();
        ack.disabled = true;
        try {
          await window.ZT.api("/api/alerts/" + ack.dataset.ack + "/ack", { method: "POST" });
          window.ZT.toast("Alert acknowledged.", "ok");
          await Promise.all([loadAlerts(), loadStats()]);
        } catch (err) {
          window.ZT.toast(err.message, "error");
          ack.disabled = false;
        }
        return;
      }
      const title = event.target.closest("[data-event]");
      if (title) openEvent(title.dataset.event);
    });

    await refreshAll();
    const eventId = params.get("event");
    if (eventId) openEvent(eventId);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
