/* Login page behaviour. */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("login-form");
    const email = document.getElementById("email");
    const password = document.getElementById("password");
    const error = document.getElementById("login-error");
    const button = document.getElementById("login-btn");
    const reveal = document.getElementById("reveal-btn");

    document.querySelectorAll(".demo-account").forEach(function (account) {
      account.addEventListener("click", function () {
        email.value = account.dataset.email;
        password.value = account.dataset.password;
        error.hidden = true;
        password.focus();
      });
    });

    reveal.addEventListener("click", function () {
      const showing = password.type === "text";
      password.type = showing ? "password" : "text";
      reveal.textContent = showing ? "Show" : "Hide";
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      error.hidden = true;
      if (!email.value.trim() || !password.value) {
        error.textContent = "Enter your work email and password.";
        error.hidden = false;
        return;
      }
      window.ZT.setLoading(button, true, "Verifying…");
      try {
        const data = await window.ZT.api("/api/auth/login", {
          method: "POST",
          body: { email: email.value.trim(), password: password.value },
        });
        window.location.href = data.redirect || "/";
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
        window.ZT.setLoading(button, false);
        password.select();
      }
    });
  });
})();
