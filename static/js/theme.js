(function () {
  const KEY = "kernel-theme";
  const saved = localStorage.getItem(KEY);
  const preferDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.setAttribute("data-theme", saved || (preferDark ? "dark" : "dark"));
})();
