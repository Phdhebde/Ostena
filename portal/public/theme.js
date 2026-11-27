// Applies the theme forced by the user (light or dark) before the first
// paint; without a choice, prefers-color-scheme decides (ADR-0020, § 5).
// External and blocking: the CSP allows no inline script.
(function () {
  var theme = null;
  try {
    theme = window.localStorage.getItem("ostena.theme");
  } catch (e) {
    theme = null;
  }
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  }
})();
