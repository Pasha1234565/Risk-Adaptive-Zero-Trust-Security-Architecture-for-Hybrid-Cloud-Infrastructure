/* Shared client helpers: API access, formatting, badges, modals, toasts. */
(function () {
  "use strict";

  const DECISIONS = {
    ALLOW: {
      label: "Allow",
      tone: "allow",
      summary: "Identity, device and context satisfy policy. Access is granted with least privilege.",
    },
    CHALLENGE: {
      label: "Challenge",
      tone: "challenge",
      summary: "Step-up authentication is required before the resource is released.",
    },
    RESTRICT: {
      label: "Restrict",
      tone: "restrict",
      summary: "Access is limited to read-only and the session is placed under enhanced monitoring.",
    },
    BLOCK: {
      label: "Block",
      tone: "block",
      summary: "The request is denied and the session is terminated.",
    },
  };

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    opts.headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (opts.body && typeof opts.body !== "string") {
      opts.body = JSON.stringify(opts.body);
      opts.headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, opts);
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (err) {
      data = { detail: text || "Unexpected response" };
    }
    if (!response.ok) {
      if (response.status === 401 && !path.includes("/api/auth/login")) {
        window.location.href = "/login";
      }
      const message = data && data.detail ? data.detail : "Request failed (" + response.status + ")";
      const error = new Error(typeof message === "string" ? message : JSON.stringify(message));
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return String(iso);
    return date.toLocaleString(undefined, {
      month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  function timeAgo(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    const seconds = Math.max(0, (Date.now() - date.getTime()) / 1000);
    if (seconds < 45) return "just now";
    if (seconds < 3600) return Math.round(seconds / 60) + "m ago";
    if (seconds < 86400) return Math.round(seconds / 3600) + "h ago";
    return Math.round(seconds / 86400) + "d ago";
  }

  function decisionMeta(decision) {
    return DECISIONS[String(decision || "").toUpperCase()] || {
      label: decision || "Unknown", tone: "muted", summary: "",
    };
  }

  function decisionBadge(decision) {
    const meta = decisionMeta(decision);
    return '<span class="badge decision-' + meta.tone + '">' + escapeHtml(meta.label) + "</span>";
  }

  function riskPill(score) {
    const value = Number(score || 0);
    const cls = value >= 80 ? "critical" : value >= 60 ? "high" : "";
    return '<span class="risk-pill ' + cls + '">' + value.toFixed(0) + "</span>";
  }

  function fmtPct(value, digits) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
    return (Number(value) * 100).toFixed(digits === undefined ? 1 : digits) + "%";
  }

  function int(value) {
    return Number(value || 0).toLocaleString();
  }

  function toast(message, type) {
    const wrap = document.getElementById("toast-wrap");
    if (!wrap) return;
    const el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.textContent = message;
    wrap.appendChild(el);
    window.setTimeout(function () {
      el.style.opacity = "0";
      el.style.transition = "opacity .25s";
      window.setTimeout(function () { el.remove(); }, 260);
    }, 4200);
  }

  let escapeHandler = null;

  function openModal(title, subtitle, bodyHtml) {
    closeModal();
    const root = document.getElementById("modal-root");
    if (!root) return;
    root.innerHTML =
      '<div class="modal-backdrop" id="modal-backdrop">' +
        '<div class="modal" role="dialog" aria-modal="true" aria-label="' + escapeHtml(title) + '">' +
          '<div class="modal-head">' +
            "<div><h2>" + escapeHtml(title) + "</h2>" +
            (subtitle ? "<p>" + escapeHtml(subtitle) + "</p>" : "") + "</div>" +
            '<button class="modal-close" id="modal-close" aria-label="Close">✕</button>' +
          "</div>" +
          '<div class="modal-body">' + bodyHtml + "</div>" +
        "</div>" +
      "</div>";
    const backdrop = document.getElementById("modal-backdrop");
    backdrop.addEventListener("click", function (event) {
      if (event.target === backdrop) closeModal();
    });
    document.getElementById("modal-close").addEventListener("click", closeModal);
    escapeHandler = function (event) {
      if (event.key === "Escape") closeModal();
    };
    document.addEventListener("keydown", escapeHandler);
  }

  function closeModal() {
    const root = document.getElementById("modal-root");
    if (root) root.innerHTML = "";
    if (escapeHandler) {
      document.removeEventListener("keydown", escapeHandler);
      escapeHandler = null;
    }
  }

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch (err) {
      /* cookie is cleared on the redirect regardless */
    }
    window.location.href = "/login";
  }

  async function refreshAlertBadge() {
    const badge = document.getElementById("alert-badge");
    if (!badge) return;
    try {
      const data = await api("/api/alerts?status=open&limit=1");
      if (data.open_count > 0) {
        badge.textContent = data.open_count > 99 ? "99+" : String(data.open_count);
        badge.hidden = false;
      } else {
        badge.hidden = true;
      }
    } catch (err) {
      badge.hidden = true;
    }
  }

  function setLoading(button, loading, label) {
    if (!button) return;
    if (loading) {
      button.dataset.originalText = button.innerHTML;
      button.disabled = true;
      button.innerHTML = '<span class="spinner"></span>' + (label || "Working…");
    } else {
      button.disabled = false;
      if (button.dataset.originalText) button.innerHTML = button.dataset.originalText;
    }
  }

  function initLayout() {
    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) logoutBtn.addEventListener("click", logout);

    const menuBtn = document.getElementById("menu-btn");
    if (menuBtn) {
      menuBtn.addEventListener("click", function () {
        document.body.classList.toggle("nav-open");
      });
      document.querySelectorAll(".nav-item").forEach(function (link) {
        link.addEventListener("click", function () {
          document.body.classList.remove("nav-open");
        });
      });
      document.addEventListener("click", function (event) {
        if (!document.body.classList.contains("nav-open")) return;
        if (event.target.closest(".sidebar") || event.target.closest("#menu-btn")) return;
        document.body.classList.remove("nav-open");
      });
    }

    const refresh = document.getElementById("refresh-dashboard");
    if (refresh) refresh.addEventListener("click", function () { window.location.reload(); });

    refreshAlertBadge();
    window.setInterval(refreshAlertBadge, 60000);
  }

  document.addEventListener("DOMContentLoaded", initLayout);

  window.ZT = {
    api: api,
    escape: escapeHtml,
    fmtTime: fmtTime,
    timeAgo: timeAgo,
    decisionMeta: decisionMeta,
    decisionBadge: decisionBadge,
    riskPill: riskPill,
    fmtPct: fmtPct,
    int: int,
    toast: toast,
    openModal: openModal,
    closeModal: closeModal,
    logout: logout,
    setLoading: setLoading,
    refreshAlertBadge: refreshAlertBadge,
    DECISIONS: DECISIONS,
  };
})();
