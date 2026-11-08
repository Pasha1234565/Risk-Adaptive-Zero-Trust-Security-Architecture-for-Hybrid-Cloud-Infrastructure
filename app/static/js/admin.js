/* Administration: inventory, policies, thresholds and model retraining. */
(function () {
  "use strict";

  const state = { data: null };

  const WEIGHT_LABELS = {
    behaviour: "Behavioural anomaly",
    device: "Device posture",
    identity: "Identity / MFA",
    resource: "Resource sensitivity",
    request: "Request pattern",
    session: "Session context",
  };

  function trustCell(score) {
    const value = Number(score);
    const cls = value < 50 ? "low" : value < 75 ? "medium" : "";
    return '<div class="trust-meter"><div class="trust-track"><span class="' + cls +
      '" style="width:' + Math.max(0, Math.min(100, value)) + '%"></span></div>' +
      '<span class="trust-value">' + value.toFixed(0) + "</span></div>";
  }

  function renderKpis(data) {
    const enabled = data.policies.filter(function (policy) { return policy.enabled; }).length;
    document.getElementById("admin-kpis").innerHTML = [
      { label: "Identities", value: data.users.length, foot: data.users.filter(function (u) { return u.mfa_enabled; }).length + " with MFA", tone: "accent" },
      { label: "Devices", value: data.devices.length, foot: data.devices.filter(function (d) { return d.managed; }).length + " managed", tone: "" },
      { label: "Resources", value: data.resources.length, foot: "Across two trust zones", tone: "" },
      { label: "Policies", value: data.policies.length, foot: enabled + " enabled", tone: enabled ? "ok" : "warn" },
    ].map(function (item) {
      return '<div class="kpi ' + item.tone + '"><div class="kpi-label">' + window.ZT.escape(item.label) +
        '</div><div class="kpi-value">' + item.value + '</div><div class="kpi-foot">' +
        window.ZT.escape(item.foot) + "</div></div>";
    }).join("");
  }

  function renderUsers(data) {
    document.querySelector("#users-table tbody").innerHTML = data.users.map(function (user) {
      const devices = (user.devices || []).map(function (device) {
        return "<span>" + window.ZT.escape(device.name) + " · " + Number(device.trust_score).toFixed(0) + "</span>";
      }).join("");
      return (
        "<tr>" +
          '<td><span class="strong">' + window.ZT.escape(user.name) + "</span>" +
            '<div class="zone-tag">' + window.ZT.escape(user.email) + "</div></td>" +
          '<td><span class="chip">' + window.ZT.escape(user.role.replace(/_/g, " ")) + "</span></td>" +
          "<td>" + window.ZT.escape(user.department) + "</td>" +
          '<td>' + (user.status === "active"
            ? '<span class="status-chip ok"><span class="pulse"></span>active</span>'
            : '<span class="status-chip danger">suspended</span>') + "</td>" +
          '<td><span class="chip">' + (user.mfa_enabled ? "Enrolled" : "Not enrolled") + "</span></td>" +
          '<td><div class="device-mini">' + (devices || '<span>none</span>') + "</div></td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderDevices(data) {
    const owners = {};
    data.users.forEach(function (user) { owners[user.id] = user.name; });
    document.querySelector("#devices-table tbody").innerHTML = data.devices.map(function (device) {
      return (
        "<tr>" +
          '<td class="strong">' + window.ZT.escape(device.name) + "</td>" +
          "<td>" + window.ZT.escape(owners[device.user_id] || "—") + "</td>" +
          '<td><span class="chip">' + window.ZT.escape(device.kind) + "</span></td>" +
          "<td>" + window.ZT.escape(device.os) + "</td>" +
          "<td>" + (device.managed ? '<span class="chip">Managed</span>' : '<span class="chip">Unmanaged</span>') + "</td>" +
          "<td>" + (device.compliant ? '<span class="chip">Compliant</span>' : '<span class="chip">Non-compliant</span>') + "</td>" +
          "<td>" + trustCell(device.trust_score) + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderResources(data) {
    document.querySelector("#resources-table tbody").innerHTML = data.resources.map(function (resource) {
      return (
        "<tr>" +
          '<td class="strong">' + window.ZT.escape(resource.name) + "</td>" +
          '<td><span class="zone-tag">' + window.ZT.escape(resource.zone) + "</span></td>" +
          "<td>" + window.ZT.escape(resource.service) + "</td>" +
          "<td>" + window.ZT.escape(resource.category) + "</td>" +
          '<td><span class="severity-tag ' + window.ZT.escape(resource.sensitivity) + '">' +
            window.ZT.escape(resource.sensitivity) + "</span></td>" +
          "<td>" + window.ZT.escape(resource.owner) + "</td>" +
        "</tr>"
      );
    }).join("");
  }

  function renderPolicies(data) {
    const enabled = data.policies.filter(function (policy) { return policy.enabled; }).length;
    document.getElementById("policy-count").textContent = enabled + " / " + data.policies.length + " enabled";
    document.querySelector("#policies-table tbody").innerHTML = data.policies.map(function (policy) {
      return (
        "<tr>" +
          '<td><span class="strong">' + window.ZT.escape(policy.name) + "</span>" +
            '<div class="zone-tag">' + window.ZT.escape(policy.description) + "</div></td>" +
          '<td><span class="chip">' + window.ZT.escape(policy.resource_category) + "</span></td>" +
          '<td class="mono">' + Number(policy.required_device_trust).toFixed(0) + "</td>" +
          "<td>" + (policy.mfa_required ? "Required" : "Optional") + "</td>" +
          "<td>" + window.ZT.escape(policy.allowed_roles || "Any role") + "</td>" +
          '<td><span class="chip">' + window.ZT.escape(policy.effect) + "</span></td>" +
          '<td><button class="toggle-btn ' + (policy.enabled ? "on" : "") + '" data-policy="' + policy.id +
            '" aria-pressed="' + (policy.enabled ? "true" : "false") + '" aria-label="Toggle policy"><span></span></button></td>' +
        "</tr>"
      );
    }).join("");
  }

  function renderModel(data) {
    const model = data.model || {};
    document.getElementById("model-detail").innerHTML = [
      ["Algorithm", model.algorithm],
      ["Baseline samples", window.ZT.int(model.samples)],
      ["Contamination", Number(model.contamination || 0).toFixed(2)],
      ["Anomaly threshold", Number(model.threshold || 0).toFixed(3)],
      ["Trained at", window.ZT.timeAgo(model.trained_at)],
      ["Features", (model.features || []).length],
    ].map(function (pair) {
      return "<div><dt>" + window.ZT.escape(pair[0]) + "</dt><dd>" + window.ZT.escape(pair[1]) + "</dd></div>";
    }).join("");
    const labels = model.feature_labels || {};
    document.getElementById("feature-chips").innerHTML = (model.features || []).map(function (feature) {
      return "<span>" + window.ZT.escape(labels[feature] || feature) + "</span>";
    }).join("");
  }

  function setThresholds(thresholds) {
    const map = [
      ["allow", thresholds.allow_max],
      ["challenge", thresholds.challenge_max],
      ["restrict", thresholds.restrict_max],
    ];
    map.forEach(function (pair) {
      document.getElementById(pair[0] + "-range").value = pair[1];
      document.getElementById(pair[0] + "-output").textContent = pair[1];
    });
  }

  function renderWeights(weights) {
    document.getElementById("weight-list").innerHTML = Object.keys(weights).map(function (key) {
      return "<div>" + window.ZT.escape(WEIGHT_LABELS[key] || key) +
        "<strong>" + Number(weights[key]).toFixed(1) + " pts</strong></div>";
    }).join("");
  }

  function renderCounts(data) {
    document.getElementById("admin-version").textContent = "v" + data.version;
    document.getElementById("system-counts").innerHTML = [
      ["Access events", window.ZT.int(data.counts.events)],
      ["Alerts", window.ZT.int(data.counts.alerts)],
      ["Evaluation runs", window.ZT.int(data.counts.evaluations)],
      ["Login attempts", window.ZT.int(data.counts.login_attempts)],
      ["Storage", "SQLite · local"],
      ["Decision plane", "FastAPI · single process"],
    ].map(function (pair) {
      return "<div><dt>" + window.ZT.escape(pair[0]) + "</dt><dd>" + window.ZT.escape(pair[1]) + "</dd></div>";
    }).join("");
  }

  function renderAll() {
    renderKpis(state.data);
    renderUsers(state.data);
    renderDevices(state.data);
    renderResources(state.data);
    renderPolicies(state.data);
    renderModel(state.data);
    setThresholds(state.data.engine.thresholds);
    renderWeights(state.data.engine.weights);
    renderCounts(state.data);
  }

  async function load() {
    try {
      state.data = await window.ZT.api("/api/admin/inventory");
      renderAll();
    } catch (err) {
      window.ZT.toast(err.message, "error");
    }
  }

  function initTabs() {
    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        document.querySelectorAll(".tab").forEach(function (item) {
          item.classList.toggle("active", item === tab);
          item.setAttribute("aria-selected", item === tab ? "true" : "false");
        });
        document.querySelectorAll(".tab-panel").forEach(function (panel) {
          panel.classList.toggle("active", panel.id === "tab-" + tab.dataset.tab);
        });
      });
    });
  }

  function initThresholds() {
    ["allow", "challenge", "restrict"].forEach(function (key) {
      const range = document.getElementById(key + "-range");
      const output = document.getElementById(key + "-output");
      range.addEventListener("input", function () { output.textContent = range.value; });
    });

    document.getElementById("threshold-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      const thresholds = {
        allow_max: Number(document.getElementById("allow-range").value),
        challenge_max: Number(document.getElementById("challenge-range").value),
        restrict_max: Number(document.getElementById("restrict-range").value),
      };
      if (!(thresholds.allow_max < thresholds.challenge_max && thresholds.challenge_max < thresholds.restrict_max)) {
        window.ZT.toast("Thresholds must be strictly increasing: Allow < Challenge < Restrict.", "warn");
        return;
      }
      const button = document.getElementById("save-thresholds");
      window.ZT.setLoading(button, true, "Saving…");
      try {
        const data = await window.ZT.api("/api/admin/settings", { method: "PUT", body: { thresholds: thresholds } });
        state.data.engine.thresholds = data.thresholds;
        setThresholds(data.thresholds);
        window.ZT.toast("Decision thresholds updated. The next request uses them.", "ok");
      } catch (err) {
        window.ZT.toast(err.message, "error");
      } finally {
        window.ZT.setLoading(button, false);
      }
    });
  }

  function initRetrain() {
    document.getElementById("retrain-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      const samples = Number(document.getElementById("train-samples").value);
      const contamination = Number(document.getElementById("train-contamination").value);
      if (samples < 200 || samples > 5000) {
        window.ZT.toast("Baseline samples must be between 200 and 5000.", "warn");
        return;
      }
      if (!(contamination >= 0.01 && contamination <= 0.15)) {
        window.ZT.toast("Contamination must be between 0.01 and 0.15.", "warn");
        return;
      }
      const button = document.getElementById("retrain-btn");
      window.ZT.setLoading(button, true, "Training…");
      try {
        const data = await window.ZT.api("/api/admin/model/train", {
          method: "POST",
          body: { samples: samples, contamination: contamination },
        });
        state.data.model = data.model;
        renderModel(state.data);
        window.ZT.toast("Behavioural model retrained on " + window.ZT.int(data.model.samples) + " sessions.", "ok");
      } catch (err) {
        window.ZT.toast(err.message, "error");
      } finally {
        window.ZT.setLoading(button, false);
      }
    });
  }

  function initPolicies() {
    document.querySelector("#policies-table tbody").addEventListener("click", async function (event) {
      const button = event.target.closest("[data-policy]");
      if (!button) return;
      button.disabled = true;
      try {
        const data = await window.ZT.api("/api/admin/policies/" + button.dataset.policy + "/toggle", { method: "POST" });
        const policy = state.data.policies.find(function (item) { return item.id === Number(button.dataset.policy); });
        if (policy) policy.enabled = data.enabled;
        renderPolicies(state.data);
        renderKpis(state.data);
        window.ZT.toast("Policy " + (data.enabled ? "enabled" : "disabled") + ".", "ok");
      } catch (err) {
        window.ZT.toast(err.message, "error");
        button.disabled = false;
      }
    });
  }

  async function init() {
    initTabs();
    initThresholds();
    initRetrain();
    initPolicies();
    await load();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
