/** Scripts communs : menu mobile, thème, effet typewriter, déconnexion. */
import { api } from "./api.js";

const toggle = document.querySelector("[data-nav-toggle]");
const nav = document.getElementById("nav-principale");
if (toggle && nav) {
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
}

document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const root = document.documentElement;
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("kernel-theme", next);
  });
});

const tw = document.querySelector("[data-typewriter]");
if (tw) {
  const full = tw.textContent;
  tw.textContent = "";
  let i = 0;
  const tick = () => {
    if (i <= full.length) {
      tw.textContent = full.slice(0, i);
      i += 1;
      setTimeout(tick, 18 + Math.random() * 25);
    }
  };
  tick();
}

document.querySelectorAll("[data-logout]").forEach((form) => {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await api("/api/auth/logout", { method: "POST", body: {} });
    location.href = "/";
  });
});
