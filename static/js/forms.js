/** Formulaires auth + contact + indicateur de robustesse du mot de passe. */
import { api } from "./api.js";

function showMsg(form, text, ok) {
  const el = form.querySelector(".form-msg");
  if (!el) return;
  el.hidden = false;
  el.textContent = text;
  el.className = "form-msg " + (ok ? "ok" : "error");
}

function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s += 1;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw)) s += 1;
  if (pw.length >= 12 || /[^A-Za-z0-9]/.test(pw)) s += 1;
  return Math.min(3, s);
}

document.querySelectorAll("[data-pw-strength]").forEach((input) => {
  const meter = input.parentElement.querySelector(".pw-meter");
  const hint = input.parentElement.querySelector("[data-pw-hint]");
  input.addEventListener("input", () => {
    const lvl = strength(input.value);
    if (meter) meter.dataset.level = String(lvl);
    if (hint) {
      hint.textContent = ["Trop court / faible", "Correct", "Solide", "Robuste"][lvl];
    }
  });
});

const handlers = {
  async register(form) {
    const fd = new FormData(form);
    const data = await api("/api/auth/register", {
      method: "POST",
      body: {
        username: fd.get("username"),
        email: fd.get("email"),
        password: fd.get("password"),
        domain: fd.get("domain"),
      },
    });
    location.href = data.redirect || "/app";
  },
  async login(form) {
    const fd = new FormData(form);
    const data = await api("/api/auth/login", {
      method: "POST",
      body: { username: fd.get("username"), password: fd.get("password") },
    });
    location.href = data.redirect || "/app";
  },
  async forgot(form) {
    const fd = new FormData(form);
    const username = fd.get("username");
    const data = await api("/api/auth/forgot", { method: "POST", body: { username } });
    const reset = document.getElementById("reset-form");
    reset.hidden = false;
    document.getElementById("reset-username").value = username;
    if (data.found && data.code) {
      const box = document.getElementById("code-box");
      box.hidden = false;
      document.getElementById("code-value").textContent = data.code;
      showMsg(form, data.message, true);
    } else {
      showMsg(form, data.message || "Si ce compte existe, un code a été généré.", true);
    }
  },
  async reset(form) {
    const fd = new FormData(form);
    const data = await api("/api/auth/reset", {
      method: "POST",
      body: {
        username: fd.get("username"),
        code: fd.get("code"),
        password: fd.get("password"),
      },
    });
    showMsg(form, data.message, true);
    setTimeout(() => { location.href = "/connexion"; }, 1200);
  },
  async contact(form) {
    const fd = new FormData(form);
    await api("/api/contact", {
      method: "POST",
      body: {
        name: fd.get("name"),
        email: fd.get("email"),
        subject: fd.get("subject"),
        body: fd.get("body"),
        website: fd.get("website") || "",
      },
    });
    form.reset();
    showMsg(form, "Message envoyé, merci !", true);
  },
};

document.querySelectorAll("form[data-form]").forEach((form) => {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const kind = form.dataset.form;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;
    try {
      await handlers[kind](form);
    } catch (err) {
      showMsg(form, err.message || "Erreur", false);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
});
