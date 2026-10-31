import { api } from "./api.js";

const hint = document.getElementById("dist-hint");
const dist = document.getElementById("demo-dist");
function updateHint() {
  const v = dist.value;
  hint.textContent = {
    broadcast: "La clé est envoyée en clair à tous les clients (faille volontaire : Ève la voit).",
    password: "Chaque conversation saisit un mot de passe commun ; clé dérivée par PBKDF2 dans le navigateur. Le serveur ne relaie que le sel.",
    x25519: "Chaque navigateur publie sa clé publique X25519 ; clé de session = SHA-256(secret partagé). Privée en IndexedDB.",
  }[v];
}
dist.addEventListener("change", updateHint); updateHint();

function setCurrent(s) {
  document.getElementById("demo-current").textContent =
    `algo=${s.algo} · ${s.key_distribution} · step=${s.presentation_step}`;
  document.getElementById("key-preview").textContent =
    `clé : ${(s.broadcast_key_hex || "").slice(0, 16)}…`;
  document.getElementById("demo-algo").value = s.algo;
  document.getElementById("demo-dist").value = s.key_distribution;
  document.querySelectorAll("#pres-list li").forEach((li) => {
    li.classList.toggle("active", Number(li.dataset.step) === s.presentation_step);
  });
}

document.getElementById("btn-save-demo").addEventListener("click", async () => {
  const body = {
    algo: document.getElementById("demo-algo").value,
    key_distribution: dist.value,
  };
  const s = await api("/api/admin/demo", { method: "PUT", body });
  setCurrent(s);
});

document.getElementById("btn-new-key").addEventListener("click", async () => {
  const s = await api("/api/admin/demo/new-key", { method: "POST", body: {} });
  setCurrent(s);
});
document.getElementById("btn-des-key")?.addEventListener("click", async () => {
  if (!confirm("Passer en DES-CBC avec une clé de 24 bits (force brute démonstrative) ?")) return;
  const s = await api("/api/admin/demo/des-short-key", { method: "POST", body: {} });
  setCurrent(s);
});

document.getElementById("btn-pres-next").addEventListener("click", async () => {
  const s = await api("/api/admin/demo/presentation/next", { method: "POST", body: {} });
  setCurrent(s);
});
document.getElementById("btn-pres-reset").addEventListener("click", async () => {
  const s = await api("/api/admin/demo/presentation/reset", { method: "POST", body: {} });
  setCurrent(s);
});

async function loadUsers() {
  const rows = await api("/api/admin/users");
  const tb = document.querySelector("#users-table tbody");
  tb.innerHTML = "";
  for (const u of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">@${u.username} ${u.online ? "●" : ""}</td>
      <td>${u.role}</td>
      <td>${u.is_suspended ? "suspendu" : "actif"}</td>
      <td class="btn-row"></td>`;
    const actions = tr.querySelector("td:last-child");
    if (u.role !== "admin") {
      const b1 = document.createElement("button");
      b1.className = "btn btn-ghost"; b1.textContent = u.is_suspended ? "Réactiver" : "Suspendre";
      b1.onclick = async () => { await api(`/api/admin/users/${u.id}/suspend`, { method: "POST", body: {} }); loadUsers(); };
      const b2 = document.createElement("button");
      b2.className = "btn btn-ghost"; b2.textContent = "Reset MDP";
      b2.onclick = async () => {
        const r = await api(`/api/admin/users/${u.id}/reset-password`, { method: "POST", body: {} });
        alert(`Mot de passe temporaire : ${r.temporary_password}`);
      };
      const b3 = document.createElement("button");
      b3.className = "btn btn-ghost"; b3.textContent = "Supprimer";
      b3.onclick = async () => {
        if (!confirm(`Supprimer @${u.username} ?`)) return;
        await api(`/api/admin/users/${u.id}`, { method: "DELETE" });
        loadUsers();
      };
      actions.append(b1, b2, b3);
    }
    tb.appendChild(tr);
  }
}

async function loadRooms() {
  const rows = await api("/api/admin/rooms");
  const ul = document.getElementById("rooms-list");
  ul.innerHTML = rows.map((r) =>
    `<li><span class="mono">${r.title}</span> <button data-id="${r.id}" class="btn btn-ghost" type="button">✕</button></li>`).join("");
  ul.querySelectorAll("button").forEach((b) => b.onclick = async () => {
    await api(`/api/admin/rooms/${b.dataset.id}`, { method: "DELETE" }); loadRooms();
  });
}
document.getElementById("room-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await api("/api/admin/rooms", { method: "POST", body: {
    title: fd.get("title"), slug: fd.get("slug"), domain: "autre", description: "",
  }});
  e.target.reset(); loadRooms();
});

async function loadEvents() {
  const rows = await api("/api/admin/events");
  const ul = document.getElementById("events-list");
  ul.innerHTML = rows.length ? rows.map((e) =>
    `<li><strong>${e.title}</strong> <span class="muted mono">${e.starts_at}</span>
     <button data-id="${e.id}" class="btn btn-ghost" type="button">✕</button></li>`).join("")
    : `<li class="muted">Aucun événement.</li>`;
  ul.querySelectorAll("button").forEach((b) => b.onclick = async () => {
    await api(`/api/admin/events/${b.dataset.id}`, { method: "DELETE" }); loadEvents();
  });
}
document.getElementById("event-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const local = fd.get("starts_at"); // datetime-local
  const iso = new Date(local).toISOString();
  await api("/api/admin/events", { method: "POST", body: {
    title: fd.get("title"), kind: fd.get("kind"), starts_at: iso, description: "",
  }});
  e.target.reset(); loadEvents();
});

async function loadContact() {
  const rows = await api("/api/admin/contact");
  const ul = document.getElementById("contact-list");
  ul.innerHTML = rows.length ? rows.map((m) =>
    `<li><strong>${m.subject}</strong> — ${m.name} &lt;${m.email}&gt;
     ${m.is_read ? "" : `<button data-id="${m.id}" class="btn btn-ghost" type="button">Marquer lu</button>`}
     <div class="muted">${m.body.slice(0, 120)}</div></li>`).join("")
    : `<li class="muted">Boîte vide.</li>`;
  ul.querySelectorAll("button").forEach((b) => b.onclick = async () => {
    await api(`/api/admin/contact/${b.dataset.id}/read`, { method: "POST", body: {} }); loadContact();
  });
}

async function loadReports() {
  const rows = await api("/api/admin/reports");
  const ul = document.getElementById("reports-list");
  ul.innerHTML = rows.length ? rows.map((r) =>
    `<li>#${r.id} ${r.target_type}/${r.target_id} — ${r.status}
     ${r.status === "ouvert" ? `<button type="button" class="btn btn-ghost" data-id="${r.id}">Clore</button>` : ""}
     <div class="muted">${r.reason}</div></li>`).join("")
    : `<li class="muted">Aucun signalement.</li>`;
  ul.querySelectorAll("button").forEach((b) => b.onclick = async () => {
    await api(`/api/admin/reports/${b.dataset.id}/close`, { method: "POST", body: {} });
    loadReports();
  });
}

async function loadActivity() {
  const rows = await api("/api/admin/activity");
  document.getElementById("activity-list").innerHTML = rows.map((a) =>
    `<li>${a.created_at} · ${a.action} · ${a.detail_json}</li>`).join("") || `<li class="muted">—</li>`;
}

async function refreshDash() {
  const d = await api("/api/admin/dashboard");
  document.getElementById("st-online").textContent = d.online;
  document.getElementById("st-users").textContent = d.users;
  document.getElementById("st-msgs").textContent = d.messages;
  const bars = document.getElementById("algo-bars");
  const entries = Object.entries(d.by_algo || {});
  bars.innerHTML = entries.length
    ? entries.map(([a, n]) => `<li><span class="mono">${a}</span> <strong>${n}</strong></li>`).join("")
    : `<li class="muted">Aucun message pour l'instant.</li>`;
}

loadUsers(); loadRooms(); loadEvents(); loadContact(); loadReports(); loadActivity();
setInterval(refreshDash, 5000);
