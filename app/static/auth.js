// Kozos auth segedfuggvenyek a statikus oldalakhoz.
(function () {
  "use strict";

  function redirectToLogin() {
    const next = window.location.pathname + window.location.search;
    window.location.href = "login.html?next=" + encodeURIComponent(next);
  }

  // fetch() wrapper: kuldi a cookie-t, 401-nel a login oldalra visz.
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

  // A container-be: "<nev> · Riasztasok · Elnyomasok · Meresi eredmenyek · Admin · Kijelentkezes".
  function renderUserMenu(container, user) {
    const links = ['<a href="index.html">Riasztások</a>', '<a href="suppressions.html">Elnyomások</a>',
      '<a href="/reports/4-tablazat">Mérési eredmények</a>'];
    // Admin fulek: Felhasznalok (admin), Kornyezet (admin es L2).
    if (user.role === "admin") links.push('<a href="admin.html">Admin</a>');
    else if (user.can_edit_context) links.push('<a href="hosts.html">Admin</a>');
    links.push('<a href="#" data-action="logout">Kijelentkezés</a>');
    container.innerHTML = `<span class="user-name">${escapeHtml(user.full_name || user.username)}</span>` + links.join("");
    container.querySelector('[data-action="logout"]').addEventListener("click", (ev) => {
      ev.preventDefault();
      logout();
    });
  }

  // Az admin panel alfulei; a Felhasznalok csak adminnak.
  function renderAdminTabs(container, user, active) {
    const tabs = [];
    if (user.role === "admin") tabs.push(["users", "admin.html", "Felhasználók"]);
    tabs.push(["environment", "hosts.html", "Környezet"]);
    tabs.push(["rules", "rules.html", "Wazuh szabályok"]);
    tabs.push(["status", "system.html", "Rendszerállapot"]);
    container.innerHTML = tabs.map(([key, href, label]) =>
      `<a href="${href}" class="admin-tab${key === active ? " active" : ""}"${key === active ? ' aria-current="page"' : ""}>${label}</a>`
    ).join("");
  }

  window.SIEM = { api, me, logout, renderUserMenu, renderAdminTabs, redirectToLogin };
})();
