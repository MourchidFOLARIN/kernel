/**
 * Interface Ève — flux live, interception, outils d'attaque.
 * Vocabulaire chiffrement autorisé ici (page attaquant uniquement).
 */
import { api } from "./api.js";
import { avalanche, bruteForceCaesar, bruteForceVigenere, detectECB, frequencyAnalysis, nonceReuseXor } from "./crypto/attacks.js";
import { bruteForceDES24 } from "./crypto/des-brute.js";
import { bytesToHex, bytesToUtf8 } from "./crypto/utils.js";

const feed = document.getElementById("eve-feed");
const heldList = document.getElementById("held-list");
const toggle = document.getElementById("intercept-toggle");
const held = new Map();
let desJob = null;

function wsUrl() {
  const p = location.protocol === "https:" ? "wss:" : "ws:";
  return `${p}//${location.host}/ws`;
}

let ws, delay = 1000;
function connect() {
  ws = new WebSocket(wsUrl());
  ws.addEventListener("open", () => {
    delay = 1000;
    if (toggle.checked) send({ type: "eve.intercept", active: true });
  });
  ws.addEventListener("message", (ev) => {
    try { onFrame(JSON.parse(ev.data)); } catch { /* ignore */ }
  });
  ws.addEventListener("close", () => { setTimeout(connect, delay); delay = Math.min(delay * 1.5, 8000); });
}
function send(o) { if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(o)); }

function onFrame(f) {
  if (f.type === "demo.settings") {
    document.getElementById("eve-algo").textContent = `algo : ${f.algo} / ${f.mode}`;
    document.getElementById("eve-dist").textContent = `distribution : ${f.key_distribution}`;
    document.getElementById("eve-key").textContent = f.key_distribution === "broadcast"
      ? `clé diffusée : ${f.broadcast_key_hex}`
      : "clé diffusée : — (non diffusée)";
  }
  if (f.type === "eve.raw") appendFeed(f);
  if (f.type === "eve.held") { held.set(f.hold_id, f); renderHeld(); }
  if (f.type === "eve.resolved") { held.delete(f.hold_id); renderHeld(); }
  if (f.type === "eve.mode") toggle.checked = !!f.intercept;
}

function appendFeed(f) {
  const empty = feed.querySelector(".muted");
  if (empty) empty.remove();
  const row = document.createElement("div");
  row.className = "feed-row";
  const fr = f.frame || {};
  row.innerHTML = `<span class="t">${f.at}</span> · <b>${f.sender || "?"}</b>
    · <span class="alg">${fr.algo}/${fr.mode}</span>
    · dist=${fr.key_dist || "—"}
    · <span class="ct">${(fr.ciphertext || "").slice(0, 64)}${(fr.ciphertext || "").length > 64 ? "…" : ""}</span>`;
  feed.prepend(row);
  while (feed.children.length > 200) feed.lastChild.remove();
  // Prefill tools with last ciphertext
  document.getElementById("classic-hex").value = fr.ciphertext || "";
  document.getElementById("ecb-hex").value = fr.ciphertext || "";
  document.getElementById("des-cipher").value = fr.ciphertext || "";
  document.getElementById("des-iv").value = fr.iv || "";
  if (fr.algo?.includes("DES")) {
    document.getElementById("des-mode").value = fr.mode === "ECB" ? "ECB" : "CBC";
  }
}

function renderHeld() {
  if (!held.size) {
    heldList.innerHTML = `<li class="muted">Aucun message retenu.</li>`;
    return;
  }
  heldList.innerHTML = "";
  for (const [id, h] of held) {
    const m = h.message || {};
    const li = document.createElement("li");
    li.innerHTML = `<div><b>${h.sender}</b> · ${m.algo}/${m.mode} · #${id}</div>
      <span class="mono">${m.ciphertext}</span>
      <input class="hex-edit" value="${m.ciphertext}" data-id="${id}">
      <div class="btn-row">
        <button type="button" class="btn btn-ghost" data-act="forward" data-id="${id}">Transmettre</button>
        <button type="button" class="btn btn-ghost" data-act="modify" data-id="${id}">Modifier + transmettre</button>
        <button type="button" class="btn btn-ghost" data-act="reject" data-id="${id}">Rejeter</button>
      </div>`;
    heldList.appendChild(li);
  }
  heldList.querySelectorAll("button").forEach((b) => {
    b.onclick = () => {
      const id = b.dataset.id;
      const act = b.dataset.act;
      if (act === "reject") send({ type: "eve.reject", hold_id: id });
      else if (act === "forward") send({ type: "eve.forward", hold_id: id });
      else if (act === "modify") {
        const hex = heldList.querySelector(`.hex-edit[data-id="${id}"]`).value.trim();
        send({ type: "eve.modify", hold_id: id, ciphertext: hex });
      }
    };
  });
}

toggle.addEventListener("change", () => {
  send({ type: "eve.intercept", active: toggle.checked });
});
document.getElementById("clear-feed").onclick = () => {
  feed.innerHTML = `<p class="muted">En attente de trafic…</p>`;
};

/* ---------- Outils ---------- */
document.getElementById("btn-caesar").onclick = () => {
  const hex = document.getElementById("classic-hex").value.trim();
  const tries = bruteForceCaesar(hex);
  const top = tries.slice(0, 8).map((t) =>
    `décalage ${String(t.shift).padStart(2)}  score=${t.score.toFixed(2)}  ${t.plain.slice(0, 80)}`).join("\n");
  const freq = frequencyAnalysis(tries[0].plain).slice(0, 10)
    .map(([c, n]) => `${c}:${n}`).join(" ");
  document.getElementById("classic-out").textContent =
    `Fréquences (meilleur candidat) : ${freq}\n\n${top}`;
};

document.getElementById("btn-vigenere").onclick = () => {
  const hex = document.getElementById("classic-hex").value.trim();
  const r = bruteForceVigenere(hex);
  document.getElementById("classic-out").textContent =
    `longueur estimée=${r.keyLength}  IC=${(r.ic || 0).toFixed(3)}\nclé ≈ « ${r.key} »\n` +
    `(appliquez ensuite César colonne par colonne si besoin)`;
};

const COLORS = ["#3dffb5", "#2ad4ff", "#ff6b7a", "#ffd166", "#c084fc", "#fb923c", "#34d399"];
document.getElementById("btn-ecb").onclick = () => {
  const hex = document.getElementById("ecb-hex").value.trim();
  const r = detectECB(hex, 16);
  const view = document.getElementById("ecb-view");
  view.innerHTML = "";
  const colorOf = new Map();
  let ci = 0;
  r.duplicates.forEach(([b]) => { colorOf.set(b, COLORS[ci++ % COLORS.length]); });
  r.blocks.forEach((b) => {
    const d = document.createElement("div");
    d.className = "ecb-block";
    d.title = b;
    d.style.background = colorOf.get(b) || "var(--surface)";
    view.appendChild(d);
  });
  document.getElementById("ecb-msg").textContent = r.suspicious
    ? `⚠ ${r.repeats} bloc(s) répété(s) — signature typique d'ECB`
    : "Aucun bloc répété détecté.";
};

document.getElementById("btn-nonce").onclick = () => {
  const a = document.getElementById("nonce-a").value.trim();
  const b = document.getElementById("nonce-b").value.trim();
  const x = nonceReuseXor(a, b);
  let ascii = "";
  try { ascii = bytesToUtf8(x); } catch { ascii = "(non UTF-8)"; }
  document.getElementById("nonce-out").textContent =
    `XOR hex : ${bytesToHex(x)}\nASCII approx : ${ascii}`;
};

document.getElementById("btn-ava").onclick = () => {
  const a = document.getElementById("ava-a").value.trim();
  const b = document.getElementById("ava-b").value.trim();
  const r = avalanche(a, b);
  document.getElementById("ava-out").textContent =
    `${r.bits} bits modifiés / ${r.totalBits} (${(r.ratio * 100).toFixed(1)} %)`;
};

document.getElementById("btn-des").onclick = () => {
  const out = document.getElementById("des-out");
  desJob = bruteForceDES24({
    mode: document.getElementById("des-mode").value,
    ivHex: document.getElementById("des-iv").value.trim(),
    cipherHex: document.getElementById("des-cipher").value.trim(),
    onProgress: (tried) => { out.textContent = `essais : ${tried} / ${1 << 24}`; },
  });
  const tick = () => {
    if (!desJob) return;
    const r = desJob.step();
    if (r.found) {
      out.textContent = `✓ trouvé après ${r.tried} essais\nclé = ${r.keyHex}\nclair = ${r.plain}`;
      desJob = null;
    } else if (r.done) {
      out.textContent = `épuisé (${r.tried} essais) — aucune clé plausible`;
      desJob = null;
    } else {
      requestAnimationFrame(tick);
    }
  };
  requestAnimationFrame(tick);
};
document.getElementById("btn-des-stop").onclick = () => { desJob = null; };

/* Boot : charge le récent + WS */
(async function () {
  try {
    const recent = await api("/api/eve/recent?limit=30");
    for (const m of recent) {
      appendFeed({ type: "eve.raw", at: m.created_at, sender: `user#${m.sender_id}`,
        frame: { algo: m.algo, mode: m.mode, iv: m.iv, ciphertext: m.ciphertext,
                 tag: m.tag, key_dist: m.key_dist, key_fp: m.key_fp } });
    }
  } catch (e) { console.warn(e); }
  connect();
})();
