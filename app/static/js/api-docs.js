/* Swagger UI bootstrap for /api/docs.
   Kept in a static file (not inline) so the page works under script-src 'self'. */
(function () {
  "use strict";
  var root = document.getElementById("swagger-ui");
  if (!root || typeof window.SwaggerUIBundle !== "function") return;
  window.ui = window.SwaggerUIBundle({
    url: root.dataset.openapiUrl,
    dom_id: "#swagger-ui",
    layout: "BaseLayout",
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    // No calls to the public validator service (blocked by CSP and not needed locally).
    validatorUrl: null,
    presets: [window.SwaggerUIBundle.presets.apis],
  });
})();
