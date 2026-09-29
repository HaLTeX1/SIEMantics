// Shared auth helpers for the static UI pages (index, alert, admin).
(function () {
  "use strict";

  function redirectToLogin() {
    const next = window.location.pathname + window.location.search;
    window.location.href = "login.html?next=" + encodeURIComponent(next);
  }

  // fetch() wrapper: sends the session cookie, bounces to the login page on 401.
  async function api(url, opts) {
    const res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts || {}));
    if (res.status === 401) {
      redirectToLogin();
      throw new Error("Bejelentkezés szükséges");
    }
    return res;
  }

  async function me() {
    const res = await api("/api/v1/auth/me");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function logout() {
    await fetch("/api/v1/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => null);
    window.location.href = "login.html";
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  // Fills `container` with "<name> · Admin · Kijelentkezés".
  function renderUserMenu(container, user) {
    const links = [];
    if (user.role === "admin") links.push('<a href="admin.html">Admin</a>');
    links.push('<a href="#" data-action="logout">Kijelentkezés</a>');
    container.innerHTML = `<span class="user-name">${escapeHtml(user.full_name || user.username)}</span>` + links.join("");
    container.querySelector('[data-action="logout"]').addEventListener("click", (ev) => {
      ev.preventDefault();
      logout();
    });
  }

  window.SIEM = { api, me, logout, renderUserMenu, redirectToLogin };
})();
