/* Minimal dependency-free SVG/CSS charts. */
(function () {
  "use strict";

  const COLORS = {
    ALLOW: "#34d399",
    CHALLENGE: "#fbbf24",
    RESTRICT: "#fb923c",
    BLOCK: "#f87171",
    accent: "#22d3ee",
    track: "rgba(148,163,184,.1)",
  };

  function esc(value) {
    return window.ZT ? window.ZT.escape(value) : String(value);
  }

  function barChart(el, data, options) {
    if (!el) return;
    const opts = options || {};
    const max = Math.max(1, ...data.map(function (item) { return Number(item.count || 0); }));
    const html = data.map(function (item) {
      const count = Number(item.count || 0);
      const height = count === 0 ? 0 : Math.max(3, (count / max) * 100);
      const color = item.color || opts.color || "accent";
      return (
        '<div class="bar-col" title="' + esc(item.label) + ": " + count + '">' +
          '<span class="bar-value">' + (opts.format ? esc(opts.format(count)) : count) + "</span>" +
          '<div class="bar-track"><div class="bar-fill ' + esc(color) + '" style="height:' + height + '%"></div></div>' +
          '<span class="bar-label">' + esc(item.label) + "</span>" +
        "</div>"
      );
    }).join("");
    el.innerHTML = '<div class="bar-chart' + (opts.flat ? " flat" : "") + '">' + html + "</div>";
  }

  function donut(el, segments, options) {
    if (!el) return;
    const opts = options || {};
    const data = segments.filter(function (item) { return Number(item.value) > 0; });
    const total = data.reduce(function (sum, item) { return sum + Number(item.value); }, 0);
    const radius = 62;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const rings = data.length
      ? data.map(function (item) {
          const value = Number(item.value);
          const fraction = total ? value / total : 0;
          const length = fraction * circumference;
          const circle =
            '<circle cx="88" cy="88" r="' + radius + '" fill="none" stroke="' + item.color +
            '" stroke-width="14" stroke-linecap="butt" stroke-dasharray="' + length + " " +
            (circumference - length) + '" stroke-dashoffset="' + (-offset) +
            '" transform="rotate(-90 88 88)"></circle>';
          offset += length;
          return circle;
        }).join("")
      : '<circle cx="88" cy="88" r="' + radius + '" fill="none" stroke="' + COLORS.track +
        '" stroke-width="14"></circle>';

    el.innerHTML =
      '<svg class="donut-svg" viewBox="0 0 176 176" role="img" aria-label="Decision split">' +
        '<circle cx="88" cy="88" r="' + radius + '" fill="none" stroke="rgba(148,163,184,.09)" stroke-width="14"></circle>' +
        rings +
        '<text x="88" y="85" text-anchor="middle" class="donut-center-value">' + esc(opts.centerValue !== undefined ? opts.centerValue : total) + "</text>" +
        '<text x="88" y="101" text-anchor="middle" class="donut-center-label">' + esc(opts.centerLabel || "evaluated") + "</text>" +
      "</svg>";
  }

  function gauge(el, score, decision) {
    if (!el) return;
    const value = Math.max(0, Math.min(100, Number(score) || 0));
    const color = COLORS[decision] || COLORS.accent;
    const radius = 87;
    const length = Math.PI * radius;
    const filled = (value / 100) * length;
    el.innerHTML =
      '<svg class="gauge-svg" viewBox="0 0 210 122" role="img" aria-label="Risk score ' + value + ' out of 100">' +
        '<path d="M 18 108 A 87 87 0 0 1 192 108" fill="none" stroke="rgba(148,163,184,.12)" stroke-width="12" stroke-linecap="round"></path>' +
        '<path d="M 18 108 A 87 87 0 0 1 192 108" fill="none" stroke="' + color +
          '" stroke-width="12" stroke-linecap="round" stroke-dasharray="' + filled + " " + length + '"></path>' +
        '<text x="105" y="88" text-anchor="middle" class="gauge-value">' + value.toFixed(0) + "</text>" +
        '<text x="105" y="104" text-anchor="middle" class="gauge-sub">Risk score</text>' +
        '<text x="18" y="120" text-anchor="middle" class="gauge-tick">0</text>' +
        '<text x="192" y="120" text-anchor="middle" class="gauge-tick">100</text>' +
      "</svg>";
  }

  window.Charts = { barChart: barChart, donut: donut, gauge: gauge, COLORS: COLORS };
})();
