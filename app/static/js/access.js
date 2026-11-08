/* Access request console: PDP evaluation, step-up MFA, PEP preview. */
(function () {
  "use strict";

  const state = { inventory: null, result: null, challengeId: null, selectedUser: null };

  function option(value, label, selected) {
    return '<option value="' + window.ZT.escape(value) + '"' + (selected ? " selected" : "") + ">" +
      window.ZT.escape(label) + "</option>";
  }

  function populateUsers() {
    const select = document.getElementById("user-select");
    select.innerHTML = state.inventory.users.map(function (user) {
      return option(user.id, user.name + " · " + user.role.replace(/_/g, " "));
    }).join("");
    const analyst = state.inventory.users.find(function (user) { return user.role === "analyst"; });
    select.value = String((analyst || state.inventory.users[0]).id);
    select.addEventListener("change", function () {
      populateDevices();
      updateHints();
      refreshRecent();
    });
  }

  function populateDevices() {
    const userId = Number(document.getElementById("user-select").value);
    const user = state.inventory.users.find(function (item) { return item.id === userId; });
    state.selectedUser = user;
    const select = document.getElementById("device-select");
    select.innerHTML = (user.devices || []).map(function (device) {
      const posture = [];
      if (!device.managed) posture.push("unmanaged");
      if (!device.compliant) posture.push("non-compliant");
      return option(
        device.id,
        device.name + " · trust " + device.trust_score + (posture.length ? " · " + posture.join(", ") : "")
      );
    }).join("");
    document.getElementById("mfa-input").checked = Boolean(user.mfa_enabled);
    updateHints();
  }

  function populateResources() {
    const select = document.getElementById("resource-select");
    const zones = [
      { key: "private", label: "Private data centre" },
      { key: "public", label: "Public cloud" },
    ];
    select.innerHTML = zones.map(function (zone) {
      const resources = state.inventory.resources.filter(function (item) { return item.zone === zone.key; });
      return '<optgroup label="' + window.ZT.escape(zone.label) + '">' +
        resources.map(function (resource) {
          return option(resource.id, resource.name + " · " + resource.sensitivity + " · " + resource.category);
        }).join("") +
        "</optgroup>";
    }).join("");
    const finance = state.inventory.resources.find(function (item) { return item.name === "finance-db"; });
    if (finance) select.value = String(finance.id);
    updateHints();
  }

  function updateHints() {
    const user = state.selectedUser;
    if (user) {
      document.getElementById("user-hint").textContent =
        user.department + " · " + user.email + " · MFA " + (user.mfa_enabled ? "enrolled" : "not enrolled");
    }
    const deviceId = Number(document.getElementById("device-select").value);
    const device = user && (user.devices || []).find(function (item) { return item.id === deviceId; });
    if (device) {
      document.getElementById("device-hint").textContent =
        device.os + " · " + (device.managed ? "managed" : "unmanaged") + " · " +
        (device.compliant ? "compliant" : "non-compliant") + " · trust " + device.trust_score + "/100";
    }
    const resourceId = Number(document.getElementById("resource-select").value);
    const resource = state.inventory.resources.find(function (item) { return item.id === resourceId; });
    if (resource) {
      document.getElementById("resource-hint").textContent =
        resource.zone + " · " + resource.service + " · owner " + resource.owner +
        " · sensitivity " + resource.sensitivity;
    }
  }

  function currentContext() {
    return {
      geo: document.getElementById("geo-select").value,
      hour: Number(document.getElementById("hour-input").value),
      requests_last_5m: Number(document.getElementById("rate-input").value),
      failed_attempts_24h: Number(document.getElementById("failed-input").value),
      bytes_out_mb: Number(document.getElementById("bytes-input").value),
      session_minutes: Number(document.getElementById("session-input").value),
      concurrent_sessions: Number(document.getElementById("concurrent-input").value),
      new_device: document.getElementById("newdevice-input").checked,
      mfa_verified: document.getElementById("mfa-input").checked,
      threat_intel: document.getElementById("threat-select").value,
    };
  }

  function resetForm() {
    document.getElementById("hour-input").value = new Date().getHours();
    document.getElementById("rate-input").value = 5;
    document.getElementById("failed-input").value = 0;
    document.getElementById("bytes-input").value = 18;
    document.getElementById("session-input").value = 25;
    document.getElementById("concurrent-input").value = 1;
    document.getElementById("mfa-input").checked = Boolean(state.selectedUser && state.selectedUser.mfa_enabled);
    document.getElementById("newdevice-input").checked = false;
    document.getElementById("threat-select").value = "clean";
    document.getElementById("geo-select").value = "Bengaluru, IN";
    populateDevices();
    updateHints();
  }

  function signalHtml(signals) {
    return signals.map(function (signal) {
      const pct = Math.round(Math.min(1, signal.factor) * 100);
      const hot = pct >= 70 ? "critical" : pct >= 45 ? "hot" : "";
      return (
        '<div class="signal">' +
          '<div class="signal-head"><span>' + window.ZT.escape(signal.label) + "</span>" +
            "<strong>" + Number(signal.points).toFixed(1) + " / " + Number(signal.weight).toFixed(0) + "</strong></div>" +
          '<div class="signal-track"><div class="signal-fill ' + hot + '" style="width:' + pct + '%"></div></div>' +
        "</div>"
      );
    }).join("");
  }

  function reasonsHtml(reasons) {
    return reasons.map(function (reason) {
      return '<li class="reason"><span class="severity-dot ' + window.ZT.escape(reason.severity) + '"></span>' +
        "<span>" + window.ZT.escape(reason.text) + "</span></li>";
    }).join("");
  }

  function anomalyFactors(result) {
    const factors = (result.anomaly && result.anomaly.top_factors) || [];
    if (!factors.length) return "";
    return (
      '<div class="panel-block"><h3>Baseline deviation</h3><div class="feature-chips">' +
        factors.map(function (factor) {
          return "<span>" + window.ZT.escape(factor.label) + " " + window.ZT.escape(factor.value) +
            " vs " + window.ZT.escape(factor.baseline) + " (" + window.ZT.escape(factor.z) + "σ)</span>";
        }).join("") +
      "</div></div>"
    );
  }

  function renderResult(result) {
    state.result = result;
    const meta = window.ZT.decisionMeta(result.decision);
    const policy = result.policy || {};
    const challenge = result.challenge;
    if (challenge) state.challengeId = challenge.id;

    const panel = document.getElementById("decision-panel");
    panel.innerHTML =
      '<div class="result-shell">' +
        '<div class="result-banner ' + meta.tone + '">' +
          '<div class="result-copy">' +
            '<div class="result-kicker">Access decision</div>' +
            '<div class="result-word">' + window.ZT.escape(meta.label) + "</div>" +
            '<p class="result-summary">' + window.ZT.escape(meta.summary) + "</p>" +
            '<div class="result-stamp">' +
              window.ZT.decisionBadge(result.decision) +
              '<span class="chip">Event #' + window.ZT.escape(result.event_id || "—") + "</span>" +
              '<span class="chip">' + window.ZT.escape(window.ZT.fmtTime(result.ts)) + "</span>" +
              (result.step_up ? '<span class="chip">Step-up verified</span>' : "") +
            "</div>" +
          "</div>" +
          '<div class="gauge-wrap" id="risk-gauge"></div>' +
        "</div>" +
        '<div class="result-stats">' +
          '<div class="result-stat"><span>Anomaly score</span><strong>' + Number(result.anomaly_score).toFixed(2) + "</strong></div>" +
          '<div class="result-stat"><span>Base risk</span><strong>' + Number(result.base_risk).toFixed(1) + "</strong></div>" +
          '<div class="result-stat"><span>Policy escalation</span><strong>+' + Number(policy.escalation_points || 0).toFixed(1) + "</strong></div>" +
          '<div class="result-stat"><span>Decision latency</span><strong class="mono">' + Number(result.latency_ms).toFixed(2) + " ms</strong></div>" +
        "</div>" +
        '<div class="result-body">' +
          '<div class="result-columns">' +
            '<div class="panel-block"><h3>Why this decision</h3><ul class="reason-list">' + reasonsHtml(result.reasons) + "</ul>" +
              anomalyFactors(result) + "</div>" +
            '<div class="panel-block"><h3>Signal contribution</h3><div class="signal-list">' + signalHtml(result.signals) + "</div></div>" +
          "</div>" +
        "</div>" +
        '<div class="policy-box">' +
          "<h3>Policy evaluation</h3>" +
          '<div class="policy-chips">' +
            (policy.matched && policy.matched.length
              ? policy.matched.map(function (name) { return '<span class="chip">' + window.ZT.escape(name) + "</span>"; }).join("")
              : '<span class="chip">No matching policy</span>') +
          "</div>" +
          '<div class="policy-meta">' +
            "<span>Device trust required: " + Number(policy.required_trust || 0).toFixed(0) + "</span>" +
            "<span>MFA required: " + (policy.mfa_required ? "yes" : "no") + "</span>" +
            "<span>Role restricted: " + (policy.role_restricted ? "yes" : "no") + "</span>" +
          "</div>" +
        "</div>" +
        (challenge ? challengeHtml(result) : "") +
        ((result.decision === "ALLOW" || result.decision === "RESTRICT")
          ? '<div class="preview-box" id="preview-box">' +
              '<div class="preview-head"><h3>Protected resource · ' + window.ZT.escape(result.resource.zone) + " zone</h3>" +
              '<button class="btn btn-ghost small" id="preview-btn">Open resource</button></div>' +
              '<div id="preview-output"><p class="preview-note">The policy enforcement point will release ' +
              (result.decision === "RESTRICT" ? "read-only, masked" : "full") + " sample records for this decision.</p></div>" +
            "</div>"
          : "") +
        (result.decision === "BLOCK"
          ? '<div class="preview-box"><div class="preview-head"><h3>Policy enforcement point</h3></div>' +
            '<p class="preview-note">Request denied. No resource data is returned and the incident is recorded for triage.</p></div>'
          : "") +
        '<details class="raw-details"><summary>Raw decision payload</summary><pre>' +
          window.ZT.escape(JSON.stringify(result, null, 2)) + "</pre></details>" +
      "</div>";

    window.Charts.gauge(document.getElementById("risk-gauge"), result.risk_score, result.decision);

    if (challenge) bindChallenge(result);
    const previewBtn = document.getElementById("preview-btn");
    if (previewBtn) previewBtn.addEventListener("click", function () { preview(result); });
  }

  function challengeHtml(result) {
    const enrolled = result.user && result.user.mfa_enabled;
    return (
      '<div class="challenge-box">' +
        "<h3>Step-up authentication required</h3>" +
        "<p>" + (enrolled
          ? "Enter the current 6-digit TOTP code. A successful check re-evaluates this request with the new context."
          : "This identity has no enrolled authenticator, so the challenge cannot be satisfied. The request remains blocked from the resource.") + "</p>" +
        (enrolled
          ? '<div class="challenge-form">' +
              '<input id="mfa-code" inputmode="numeric" maxlength="6" placeholder="000000" aria-label="Verification code">' +
              '<button class="btn btn-primary small" id="verify-mfa">Verify &amp; re-evaluate</button>' +
              '<button class="btn btn-ghost small" id="demo-code">Get demo code</button>' +
              '<span class="challenge-hint" id="challenge-hint">Local prototype: codes are generated from the enrolled TOTP secret.</span>' +
            "</div>"
          : "") +
      "</div>"
    );
  }

  function bindChallenge(result) {
    const verify = document.getElementById("verify-mfa");
    const demo = document.getElementById("demo-code");
    if (!verify) return;
    verify.addEventListener("click", async function () {
      const code = document.getElementById("mfa-code").value.trim();
      if (code.length !== 6) {
        window.ZT.toast("Enter the 6-digit verification code.", "warn");
        return;
      }
      window.ZT.setLoading(verify, true, "Verifying…");
      try {
        const updated = await window.ZT.api("/api/access/challenge", {
          method: "POST",
          body: { challenge_id: state.challengeId, code: code },
        });
        window.ZT.toast("Step-up verified. Request re-evaluated.", "ok");
        renderResult(updated);
        refreshRecent();
        window.ZT.refreshAlertBadge();
      } catch (err) {
        window.ZT.toast(err.message, "error");
        window.ZT.setLoading(verify, false);
      }
    });
    demo.addEventListener("click", async function () {
      try {
        const data = await window.ZT.api("/api/auth/totp");
        document.getElementById("mfa-code").value = data.code;
        document.getElementById("challenge-hint").textContent =
          "Demo code " + data.code + " · valid for " + data.seconds_remaining + "s. In production it stays on the enrolled device.";
      } catch (err) {
        window.ZT.toast(err.message, "error");
      }
    });
  }

  async function preview(result) {
    const output = document.getElementById("preview-output");
    const button = document.getElementById("preview-btn");
    window.ZT.setLoading(button, true, "Opening…");
    try {
      const data = await window.ZT.api("/api/access/preview", {
        method: "POST",
        body: { event_id: result.event_id },
      });
      const rows = data.records || [];
      const keys = rows.length ? Object.keys(rows[0]) : [];
      output.innerHTML =
        '<div class="preview-head"><span class="chip">' + window.ZT.escape(data.scope) + " scope</span>" +
        '<span class="preview-note">' + Number(data.service_latency_ms).toFixed(2) + " ms service latency</span></div>" +
        (rows.length
          ? '<table class="preview-table"><thead><tr>' +
              keys.map(function (key) { return "<th>" + window.ZT.escape(key) + "</th>"; }).join("") +
            "</tr></thead><tbody>" +
              rows.map(function (row) {
                return "<tr>" + keys.map(function (key) {
                  return "<td>" + window.ZT.escape(row[key]) + "</td>";
                }).join("") + "</tr>";
              }).join("") +
            "</tbody></table>"
          : '<p class="preview-note">No records returned.</p>') +
        '<p class="preview-note">' + window.ZT.escape(data.notice) + "</p>";
    } catch (err) {
      output.innerHTML = '<p class="preview-note" style="color:var(--block)">' + window.ZT.escape(err.message) + "</p>";
    } finally {
      window.ZT.setLoading(button, false);
    }
  }

  async function evaluate(event) {
    event.preventDefault();
    const button = document.getElementById("evaluate-btn");
    window.ZT.setLoading(button, true, "Evaluating…");
    try {
      const payload = {
        user_id: Number(document.getElementById("user-select").value),
        device_id: Number(document.getElementById("device-select").value),
        resource_id: Number(document.getElementById("resource-select").value),
        context: currentContext(),
      };
      const result = await window.ZT.api("/api/access/evaluate", { method: "POST", body: payload });
      renderResult(result);
      refreshRecent();
      window.ZT.refreshAlertBadge();
    } catch (err) {
      window.ZT.toast(err.message, "error");
    } finally {
      window.ZT.setLoading(button, false);
    }
  }

  async function refreshRecent() {
    const tbody = document.querySelector("#access-recent tbody");
    if (!tbody) return;
    try {
      const data = await window.ZT.api("/api/events?limit=6");
      if (!data.events.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty compact">No evaluations yet.</td></tr>';
        return;
      }
      tbody.innerHTML = data.events.map(function (event) {
        return (
          "<tr>" +
            '<td class="nowrap">' + window.ZT.timeAgo(event.ts) + "</td>" +
            '<td class="strong">' + window.ZT.escape(event.user_name) + "</td>" +
            "<td>" + window.ZT.escape(event.device_name) + "</td>" +
            "<td>" + window.ZT.escape(event.resource_name) + "</td>" +
            "<td>" + window.ZT.riskPill(event.risk_score) + "</td>" +
            "<td>" + window.ZT.decisionBadge(event.decision) + "</td>" +
            '<td><a class="arrow-link" href="/monitoring?event=' + event.id + '" aria-label="Open event">' +
              '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 6l6 6-6 6"/></svg></a></td>' +
          "</tr>"
        );
      }).join("");
    } catch (err) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty compact">' + window.ZT.escape(err.message) + "</td></tr>";
    }
  }

  async function init() {
    try {
      state.inventory = await window.ZT.api("/api/context/inventory");
      const geo = document.getElementById("geo-select");
      geo.innerHTML = state.inventory.geo_presets.map(function (name) {
        return option(name, name);
      }).join("");
      geo.value = "Bengaluru, IN";
      document.getElementById("hour-input").value = new Date().getHours();
      populateUsers();
      populateDevices();
      populateResources();
      refreshRecent();
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }

    document.getElementById("access-form").addEventListener("submit", evaluate);
    document.getElementById("reset-form").addEventListener("click", resetForm);
    document.getElementById("user-select").addEventListener("change", function () { populateDevices(); updateHints(); });
    document.getElementById("device-select").addEventListener("change", updateHints);
    document.getElementById("resource-select").addEventListener("change", updateHints);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
