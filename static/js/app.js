/**
 * Kernel — messagerie /app. POINT D'ENTRÉE UNIQUE de l'interface de discussion.
 *
 * Principes (suite au retour « les boutons ne marchent pas ») :
 *  1. Tous les gestionnaires sont attachés tout de suite, par DÉLÉGATION sur #app
 *     (attribut data-action), avant le moindre appel réseau : un bouton ajouté
 *     plus tard fonctionne automatiquement, et une erreur réseau ne peut pas
 *     empêcher l'installation des boutons.
 *  2. Chaque action donne un retour visible (toast succès / erreur).
 *  3. Le chiffrement est chargé à part (import dynamique) : s'il échoue, la
 *     messagerie en clair continue de fonctionner.
 */
import { api } from "./api.js";
import { bindCopyButtons, renderMarkdown } from "./markdown.js";

const root = document.getElementById("app");
const $ = (id) => document.getElementById(id);
const meId = Number(root.dataset.userId);
const myRole = root.dataset.role || "membre";
const demoMode = root.dataset.demoMode === "true";
const showCoulisses = demoMode && (myRole === "admin" || myRole === "attaquant");
const QUICK_REACTIONS = ["👍", "❤️", "😂", "🎉", "😮", "😢"];

const state = {
  tab: "chats", convs: [], convsLoaded: false, active: null, messages: [],
  members: [], membersLoaded: false, rooms: [], contacts: [],
  online: new Set(),
  settings: { algo: "Aucun", mode: "clair", key_distribution: "broadcast", broadcast_key_hex: "" },
  meta: new Map(), replyTo: null, pendingFile: null,
  typing: false, typingTimer: null, typingHideTimer: null, keyRetry: null,
  groupSel: new Set(), pickIndex: 0,
};

/* ---------- Petits utilitaires ---------- */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const norm = (s) => String(s ?? "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "");
const clientId = () => (globalThis.crypto?.randomUUID ? crypto.randomUUID()
  : Date.now().toString(36) + Math.random().toString(36).slice(2));
const utf8ToHex = (t) => Array.from(new TextEncoder().encode(t), (b) => b.toString(16).padStart(2, "0")).join("");
function hexToUtf8(h) {
  const s = String(h || "");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return new TextDecoder().decode(out);
}
const toDate = (iso) => new Date(iso && !/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso + "Z" : iso);
const fmtTime = (iso) => (iso ? toDate(iso).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }) : "");
function fmtShort(iso) {
  if (!iso) return "";
  const d = toDate(iso), now = new Date();
  if (d.toDateString() === now.toDateString()) return fmtTime(iso);
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" });
}
function fmtDay(iso) {
  const d = toDate(iso), now = new Date();
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === now.toDateString()) return "Aujourd'hui";
  if (d.toDateString() === y.toDateString()) return "Hier";
  return d.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long" });
}
function hue(s) { let h = 0; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; }
function initials(name) {
  const parts = String(name || "?").trim().split(/[\s._-]+/).filter(Boolean);
  return ((parts[0]?.[0] || "?") + (parts[1]?.[0] || parts[0]?.[1] || "")).toUpperCase();
}
const withTimeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("délai dépassé")), ms))]);
const isOnline = (id) => state.online.has(Number(id));
const domainLabels = Object.fromEntries([...document.querySelectorAll('#settings-form select[name="domain"] option')]
  .map((o) => [o.value, o.textContent.trim()]));
const domainLabel = (d) => domainLabels[d] || d || "";

/* ---------- Retour visuel ---------- */
function toast(msg, kind = "error") {
  const box = $("toasts");
  if (!box) return;
  const t = document.createElement("div");
  t.className = "toast toast-" + kind;
  t.setAttribute("role", kind === "error" ? "alert" : "status");
  t.textContent = msg;
  box.appendChild(t);
  setTimeout(() => t.classList.add("out"), 4200);
  setTimeout(() => t.remove(), 4700);
}
const ok = (msg) => toast(msg, "ok");
function setConn(st) {
  const el = $("conn-status");
  el.dataset.state = st;
  el.hidden = st === "online";
  el.textContent = st === "offline" ? "Connexion perdue — reconnexion en cours…" : "Connexion au serveur…";
}
window.addEventListener("unhandledrejection", (e) => {
  const m = e.reason?.message || String(e.reason || "");
  if (m) toast("Erreur : " + m);
});

/* ---------- Chiffrement (chargé à part, jamais bloquant) ---------- */
let C = null, K = null;
const cryptoReady = (async () => {
  try {
    const [c, k] = await Promise.all([import("./crypto/index.js"), import("./crypto/keymanager.js")]);
    C = c; K = k;
    try { await withTimeout(K.init(), 8000); } catch (e) { console.warn("Initialisation des clés :", e); }
    return true;
  } catch (e) {
    console.error("Module de chiffrement indisponible :", e);
    return false;
  }
})();

function decode(msg) {
  const cached = state.meta.get(msg.id) ?? state.meta.get(msg.client_id);
  if (cached?.plain != null) return { ok: true, plain: cached.plain, meta: cached };
  if (!msg.algo || msg.algo === "Aucun") {
    try { return { ok: true, plain: hexToUtf8(msg.ciphertext), meta: { keyDisplay: "—", integrity: true } }; }
    catch { return { ok: false, plain: "", error: "format invalide", meta: {} }; }
  }
  if (!C || !K) return { ok: false, pending: true, plain: "", error: "chargement", meta: {} };
  const keyHex = K.keyForMessage(msg, state.settings);
  if (keyHex === null) return { ok: false, plain: "", error: "clé indisponible sur cet appareil", meta: { keyDisplay: "—", integrity: null } };
  const res = C.decrypt(msg, keyHex);
  if (res.ok) state.meta.set(msg.id, { ...res.meta, plain: res.plain });
  return res;
}
function encodeText(text, algo, keyHex) {
  if (algo === "Aucun") return { algo: "Aucun", mode: "clair", iv: "", ciphertext: utf8ToHex(text), tag: "", meta: { plain: text, keyDisplay: "—", integrity: true } };
  return C.encrypt(text, algo, keyHex);
}

/* ---------- Boîtes de dialogue ---------- */
function openDialog(dlg) {
  if (!dlg) return;
  if (typeof dlg.showModal === "function") { if (!dlg.open) dlg.showModal(); }
  else dlg.setAttribute("open", "");
}
function closeDialog(dlg) {
  if (!dlg) return;
  if (typeof dlg.close === "function") { if (dlg.open) dlg.close(); }
  else dlg.removeAttribute("open");
}
let askResolve = null;
/** Remplace prompt()/confirm() : renvoie le texte saisi, true, ou null si annulé. */
function ask({ title, text = "", input = false, value = "", okLabel = "OK", danger = false }) {
  const dlg = $("ask-dlg");
  $("ask-title").textContent = title;
  $("ask-text").textContent = text;
  $("ask-text").hidden = !text;
  const inp = $("ask-input");
  inp.hidden = !input; inp.value = value;
  const okBtn = $("ask-ok");
  okBtn.textContent = okLabel;
  okBtn.classList.toggle("danger", danger);
  if (askResolve) askResolve(null);
  return new Promise((resolve) => {
    askResolve = resolve;
    openDialog(dlg);
    setTimeout(() => (input ? inp : okBtn).focus(), 30);
  });
}
function finishAsk(value) {
  const r = askResolve; askResolve = null;
  closeDialog($("ask-dlg"));
  if (r) r(value);
}

/* ---------- Rendu : avatars, listes ---------- */
function avatarHtml(u, pres) {
  const name = u?.display_name || u?.username || "?";
  const img = u?.avatar ? `<img src="${esc(u.avatar)}" alt="">` : esc(initials(name));
  const dot = pres === undefined ? "" : `<i class="pres${pres ? " on" : ""}" aria-hidden="true"></i>`;
  return `<span class="avatar" style="--h:${hue(u?.username || name)}" aria-hidden="true">${img}${dot}</span>`;
}
const currentConv = () => state.convs.find((c) => c.id === state.active) || null;
function convName(c) {
  if (!c) return "";
  if (c.kind === "dm") return c.other?.display_name || c.other?.username || "Conversation";
  return c.title || (c.kind === "room" ? "Salon" : "Groupe");
}
function convPreview(c) {
  const lm = c.last_message;
  if (!lm) return c.kind === "dm" ? "Dites bonjour 👋" : "Aucun message pour l'instant";
  let p;
  if (lm.deleted) p = "Message supprimé";
  else { const d = decode(lm); p = d.ok ? d.plain.replace(/\s+/g, " ") : "Nouveau message"; }
  if (lm.sender_id === meId) return "Vous : " + p;
  if (c.kind !== "dm" && lm.sender_name) return lm.sender_name + " : " + p;
  return p;
}
function renderConvs() {
  const ul = $("conv-list");
  const list = state.convs;
  $("conv-empty").hidden = !state.convsLoaded || list.length > 0;
  ul.innerHTML = list.map((c) => {
    const dm = c.kind === "dm";
    const av = dm ? avatarHtml(c.other || {}, isOnline(c.other?.id))
      : `<span class="avatar avatar-room" aria-hidden="true">${c.kind === "room" ? "#" : "👥"}</span>`;
    const name = c.kind === "room" ? convName(c).replace(/^#/, "") : convName(c);
    return `<li><button type="button" class="row conv-row${c.id === state.active ? " active" : ""}${c.unread ? " unread" : ""}"
      data-action="open-conv" data-conv-id="${c.id}" aria-current="${c.id === state.active ? "true" : "false"}">
      ${av}<span class="row-main"><span class="row-title">${c.kind === "room" ? '<span class="hash">#</span>' : ""}${esc(name)}</span>
      <span class="row-sub">${esc(convPreview(c).slice(0, 90))}</span></span>
      <span class="row-end">${c.last_message ? `<time>${fmtShort(c.last_message.created_at)}</time>` : ""}
      ${c.unread ? `<span class="badge-unread" aria-label="${c.unread} non lus">${c.unread > 99 ? "99+" : c.unread}</span>` : ""}</span>
    </button></li>`;
  }).join("");
  const total = list.reduce((s, c) => s + (c.unread || 0), 0);
  const cnt = $("count-chats");
  cnt.hidden = !total; cnt.textContent = total > 99 ? "99+" : String(total);
  document.title = total ? `(${total}) Messages — Kernel` : "Messages — Kernel";
}

function sortMembers(list) {
  return [...list].sort((a, b) => (isOnline(b.id) - isOnline(a.id))
    || norm(a.display_name || a.username).localeCompare(norm(b.display_name || b.username)));
}
function filterMembers(q) {
  const n = norm(q).replace(/^@/, "").trim();
  const list = n ? state.members.filter((u) =>
    norm(u.username).includes(n) || norm(u.display_name).includes(n) || norm(domainLabel(u.domain)).includes(n)
    || norm(u.domain).includes(n)) : state.members;
  return sortMembers(list);
}
function memberRow(u, { action = "dm", extra = "", selected = null } = {}) {
  const on = isOnline(u.id);
  const sel = selected === null ? "" : ` aria-pressed="${selected}"`;
  return `<li class="member-li"><button type="button" class="row member-row${selected ? " selected" : ""}"
      data-action="${action}" data-user-id="${u.id}"${sel}>
    ${avatarHtml(u, on)}
    <span class="row-main"><span class="row-title">${esc(u.display_name || u.username)}</span>
      <span class="row-sub">@${esc(u.username)}${u.domain ? " · " + esc(domainLabel(u.domain)) : ""}</span></span>
    <span class="row-end">${selected === null ? `<span class="state${on ? " on" : ""}">${on ? "en ligne" : "hors ligne"}</span>`
      : `<span class="check" aria-hidden="true">${selected ? "✓" : ""}</span>`}</span>
  </button>${extra}</li>`;
}
function emptyMembers(q) {
  if (!state.membersLoaded) return `<li class="list-note">Chargement des membres…</li>`;
  if (!state.members.length) return `<li class="list-note">Vous êtes le premier inscrit ! Invitez d'autres personnes à rejoindre Kernel.</li>`;
  return `<li class="list-note">Aucun membre ne correspond à « ${esc(q)} ».</li>`;
}

function renderPicker() {
  const q = $("newmsg-search").value;
  const list = filterMembers(q);
  state.pickIndex = Math.min(state.pickIndex, Math.max(list.length - 1, 0));
  $("newmsg-list").innerHTML = list.length ? list.map((u) => memberRow(u)).join("") : emptyMembers(q);
  $("newmsg-list").querySelectorAll(".member-row").forEach((b, i) => b.classList.toggle("kbd", i === state.pickIndex && !!q));
  const n = state.members.length;
  $("newmsg-count").textContent = state.membersLoaded
    ? (q ? `${list.length} résultat${list.length > 1 ? "s" : ""} sur ${n} membre${n > 1 ? "s" : ""}` : `${n} membre${n > 1 ? "s" : ""} inscrit${n > 1 ? "s" : ""} — cliquez pour écrire`)
    : "";
}
function renderPeople() {
  const q = $("people-search").value;
  const list = filterMembers(q);
  $("people-list").innerHTML = list.length ? list.map((u) => memberRow(u, {
    extra: `<div class="row-actions">
      <button type="button" class="btn-sm" data-action="contact-add" data-user-id="${u.id}">＋ Contact</button>
      <button type="button" class="btn-sm" data-action="block" data-user-id="${u.id}">Bloquer</button></div>`,
  })).join("") : emptyMembers(q);
  const on = state.members.filter((u) => isOnline(u.id)).length;
  $("people-count").textContent = state.membersLoaded
    ? `${state.members.length} membre${state.members.length > 1 ? "s" : ""} · ${on} en ligne — touchez un membre pour lui écrire` : "";
}
function renderGroupPicker() {
  const q = $("group-search").value;
  const list = filterMembers(q);
  $("group-list").innerHTML = list.length
    ? list.map((u) => memberRow(u, { action: "group-toggle", selected: state.groupSel.has(u.id) })).join("") : emptyMembers(q);
  const names = state.members.filter((u) => state.groupSel.has(u.id)).map((u) => "@" + u.username);
  $("group-selected").textContent = names.length ? `Sélection (${names.length}) : ${names.join(", ")}` : "Aucun membre sélectionné.";
}
function renderOnline() {
  const on = sortMembers(state.members.filter((u) => isOnline(u.id)));
  const chip = (u) => `<button type="button" class="chip" data-action="dm" data-user-id="${u.id}" title="Écrire à ${esc(u.display_name || u.username)}">
    ${avatarHtml(u, true)}<span>${esc(u.display_name || u.username)}</span></button>`;
  $("online-strip").hidden = !on.length;
  $("online-list").innerHTML = on.slice(0, 30).map(chip).join("");
  $("home-online").innerHTML = on.length ? on.slice(0, 40).map(chip).join("")
    : `<p class="muted">Personne d'autre n'est connecté pour le moment. Vous pouvez quand même écrire : le message sera lu à la prochaine connexion.</p>`;
}
function renderMembersEverywhere() {
  renderOnline();
  if (state.tab === "people") renderPeople();
  if ($("newmsg-dlg").open) renderPicker();
  if ($("group-dlg").open) renderGroupPicker();
}
function renderRooms() {
  const joined = new Set(state.convs.filter((c) => c.kind === "room").map((c) => c.id));
  $("rooms-list").innerHTML = state.rooms.length ? state.rooms.map((r) => {
    const inIt = joined.has(r.id);
    return `<li class="member-li"><button type="button" class="row" data-action="room-open" data-room-id="${r.id}">
      <span class="avatar avatar-room" aria-hidden="true">#</span>
      <span class="row-main"><span class="row-title">${esc(r.title.replace(/^#/, ""))}</span>
      <span class="row-sub">${esc(r.description || "")} · ${r.members} membre${r.members > 1 ? "s" : ""}</span></span>
      <span class="row-end">${inIt ? '<span class="state on">membre</span>' : '<span class="pill-join">Rejoindre</span>'}</span>
    </button>${inIt ? `<div class="row-actions"><button type="button" class="btn-sm" data-action="room-leave" data-room-id="${r.id}">Quitter</button></div>` : ""}</li>`;
  }).join("") : `<li class="list-note">Aucun salon pour l'instant.</li>`;
}
function renderRequests() {
  const rows = state.contacts;
  const pending = rows.filter((c) => c.status === "pending");
  const inc = pending.filter((c) => !c.from_me), out = pending.filter((c) => c.from_me);
  const acc = rows.filter((c) => c.status === "accepted");
  const cnt = $("count-requests");
  cnt.hidden = !inc.length; cnt.textContent = String(inc.length);
  const btn = (act, label, c, primary) =>
    `<button type="button" class="btn-sm${primary ? " primary" : ""}" data-action="${act}" data-contact-id="${c.id}">${label}</button>`;
  const fill = (id, list, actions, empty) => {
    $(id).innerHTML = list.length ? list.map((c) => memberRow({ ...c.user }, {
      extra: `<div class="row-actions">${actions.map(([a, l, p]) => btn(a, l, c, p)).join("")}</div>` })).join("")
      : `<li class="list-note">${empty}</li>`;
  };
  fill("req-in", inc, [["req-accept", "Accepter", true], ["req-refuse", "Refuser"]], "Aucune demande reçue.");
  fill("req-out", out, [["req-remove", "Annuler la demande"]], "Aucune demande en attente.");
  fill("req-ok", acc, [["req-remove", "Retirer"]], "Pas encore de contact. Ajoutez-en depuis l'onglet Membres.");
}

/* ---------- Rendu : conversation ---------- */
function coulissesHtml(msg, dec) {
  if (!showCoulisses) return "";
  const meta = dec.meta || {};
  const integ = dec.ok ? (meta.integrity === false ? "échec d'intégrité" : "succès") : (dec.error || "échec");
  const integClass = dec.ok && meta.integrity !== false ? "ok" : "ko";
  return `<details class="coulisses"><summary>Coulisses</summary><dl>
    <dt>Clair</dt><dd class="mono">${esc(dec.plain || "—")}</dd>
    <dt>Algo</dt><dd class="mono">${esc(msg.algo)} / ${esc(msg.mode || "")}</dd>
    <dt>Distribution</dt><dd class="mono">${esc(msg.key_dist || "broadcast")} · fp ${esc(msg.key_fp || "—")}</dd>
    <dt>Clé</dt><dd class="mono">${esc(meta.keyDisplay || "—")}</dd>
    <dt>IV/nonce</dt><dd class="mono break">${esc(msg.iv || "—")}</dd>
    <dt>Chiffré</dt><dd class="mono break">${esc(msg.ciphertext || "")}</dd>
    <dt>Taille</dt><dd class="mono">${(msg.ciphertext || "").length / 2} octets</dd>
    <dt>Tag</dt><dd class="mono break">${esc(msg.tag || "—")}</dd>
    <dt>Déchiffrement</dt><dd class="integ ${integClass}">${esc(integ)}</dd></dl></details>`;
}
function receiptHtml(m) {
  const st = m.status || "sent";
  if (st === "failed") return `<button type="button" class="receipt failed" data-action="retry">⚠ Non envoyé — réessayer</button>`;
  if (st === "sending") return `<span class="receipt" title="Envoi…">🕓</span>`;
  const label = st === "read" ? "Lu" : st === "delivered" ? "Distribué" : "Envoyé";
  return `<span class="receipt ${st === "read" ? "read" : ""}" title="${label}">${st === "sent" ? "✓" : "✓✓"}</span>`;
}
function bubbleHtml(m, kind) {
  const mine = m.sender_id === meId;
  if (m.deleted) return `<div class="bubble deleted${mine ? " me" : ""}" data-mid="${m.id}">Message supprimé</div>`;
  const dec = decode(m);
  const text = dec.ok ? dec.plain : dec.pending ? "Déchiffrement…" : "⚠ Message illisible sur cet appareil";
  const body = dec.ok ? renderMarkdown(text) : esc(text);
  const who = !mine && kind !== "dm" ? `<div class="bubble-author" style="--h:${hue(m.sender_username || m.sender_name || "")}">${esc(m.sender_name || "Membre")}</div>` : "";
  let reply = "";
  if (m.reply_to) {
    const src = state.messages.find((x) => x.id === m.reply_to);
    const sd = src && !src.deleted ? decode(src) : null;
    reply = `<div class="bubble-reply">↩ ${esc(sd?.ok ? sd.plain.slice(0, 80) : "message #" + m.reply_to)}</div>`;
  }
  const rx = Object.entries(m.reactions || {}).map(([e, ids]) =>
    `<button type="button" class="reaction${ids.includes(meId) ? " mine" : ""}" data-action="react" data-emoji="${esc(e)}">${esc(e)} ${ids.length}</button>`).join("");
  const att = m.attachment ? `<button type="button" class="att-chip" data-action="att-open" data-att="${m.attachment.id}">📎 Ouvrir le fichier (${Math.ceil(m.attachment.size / 1024)} Ko)</button>` : "";
  const real = m.id > 0;
  const actions = real ? `<span class="bubble-actions">
      <button type="button" data-action="reply" title="Répondre" aria-label="Répondre">↩</button>
      <button type="button" data-action="react-pick" title="Réagir" aria-label="Réagir">😊</button>
      ${mine && dec.ok ? `<button type="button" data-action="edit" title="Modifier" aria-label="Modifier">✎</button>` : ""}
      ${mine ? `<button type="button" data-action="delete" title="Supprimer" aria-label="Supprimer">🗑</button>` : ""}
      ${!mine ? `<button type="button" data-action="report" title="Signaler" aria-label="Signaler">⚑</button>` : ""}
    </span>` : "";
  return `<div class="bubble${mine ? " me" : ""}${dec.ok || dec.pending ? "" : " bad"}${m.status === "failed" ? " failed" : ""}" data-mid="${m.id}" data-cid="${esc(m.client_id || "")}">
    ${who}${reply}<div class="bubble-body">${body}</div>${att}
    <div class="reactions">${rx}</div>
    <div class="react-pal" hidden>${QUICK_REACTIONS.map((e) => `<button type="button" data-action="react" data-emoji="${e}">${e}</button>`).join("")}</div>
    <div class="bubble-meta"><time>${fmtTime(m.created_at)}${m.edited_at ? " · modifié" : ""}</time>${mine ? receiptHtml(m) : ""}${actions}</div>
    ${coulissesHtml(m, dec)}</div>`;
}
function renderMessages({ keepScroll = false } = {}) {
  const box = $("chat-msgs");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const kind = currentConv()?.kind || "dm";
  if (!state.messages.length) {
    box.innerHTML = `<div class="msgs-empty"><p>Aucun message pour l'instant.</p><p class="muted">Écrivez le premier ci-dessous 👇</p></div>`;
    return;
  }
  let lastDay = "", html = "";
  for (const m of state.messages) {
    const day = m.created_at ? toDate(m.created_at).toDateString() : "";
    if (day && day !== lastDay) { html += `<div class="day-sep"><span>${esc(fmtDay(m.created_at))}</span></div>`; lastDay = day; }
    html += bubbleHtml(m, kind);
  }
  box.innerHTML = html;
  bindCopyButtons(box);
  applyMsgSearch();
  if (!keepScroll || atBottom) box.scrollTop = box.scrollHeight;
}
function applyMsgSearch() {
  const q = norm($("msg-search").value.trim());
  $("chat-msgs").querySelectorAll(".bubble").forEach((b) => { b.hidden = !!q && !norm(b.textContent).includes(q); });
}
function renderChatHeader() {
  const c = currentConv();
  if (!c) return;
  const title = $("chat-title"), sub = $("chat-sub"), av = $("chat-avatar");
  title.textContent = convName(c);
  if (c.kind === "dm") {
    const on = isOnline(c.other?.id);
    sub.textContent = `@${c.other?.username || ""} · ${on ? "en ligne" : "hors ligne"}`;
    av.outerHTML = avatarHtml(c.other || {}, on).replace('class="avatar"', 'class="avatar" id="chat-avatar"');
  } else {
    const ids = c.member_ids || [];
    const on = ids.filter((i) => i !== meId && isOnline(i)).length + 1;
    sub.textContent = `${ids.length} membre${ids.length > 1 ? "s" : ""} · ${on} en ligne`;
    av.outerHTML = `<span class="avatar avatar-room" id="chat-avatar" aria-hidden="true">${c.kind === "room" ? "#" : "👥"}</span>`;
  }
}

/* ---------- Navigation ---------- */
function showChat(show) {
  $("chat").hidden = !show;
  $("home").hidden = show;
  root.classList.toggle("show-chat", show);
}
function switchTab(tab) {
  state.tab = tab;
  for (const t of ["chats", "rooms", "people", "requests"]) {
    const btn = $("tab-" + t), pane = $("pane-" + t);
    btn.setAttribute("aria-selected", String(t === tab));
    btn.classList.toggle("active", t === tab);
    pane.hidden = t !== tab;
  }
  // Sur mobile, la liste est masquée quand une conversation est ouverte : on y revient.
  if (window.matchMedia("(max-width: 800px)").matches) { state.active = null; showChat(false); }
  if (tab === "rooms") loadRooms().catch((e) => toast("Salons indisponibles : " + e.message));
  if (tab === "people") { renderPeople(); loadMembers().catch(() => {}); }
  if (tab === "requests") { renderRequests(); loadContacts().catch((e) => toast(e.message)); }
  if (tab === "chats") renderConvs();
}

/* ---------- Chargements ---------- */
function updateAlgoBadge() {
  const b = $("algo-badge");
  if (!showCoulisses) { b.hidden = true; return; }
  b.hidden = false;
  b.textContent = `${state.settings.algo} · ${state.settings.key_distribution}`;
}
async function loadSettings() {
  try { state.settings = await api("/api/demo/settings"); updateAlgoBadge(); } catch (e) { console.warn(e); }
}
async function loadConvs() {
  state.convs = await api("/api/conversations");
  state.convsLoaded = true;
  for (const c of state.convs) if (c.other?.online) state.online.add(c.other.id);
  renderConvs();
  if (state.tab === "rooms") renderRooms();
}
async function loadMembers() {
  state.members = await api("/api/users/all");
  state.membersLoaded = true;
  for (const u of state.members) if (u.online) state.online.add(u.id);
  renderMembersEverywhere();
}
async function loadRooms() {
  state.rooms = await api("/api/rooms");
  renderRooms();
}
async function loadContacts() {
  state.contacts = await api("/api/contacts");
  renderRequests();
}

/* ---------- Ouvrir une conversation ---------- */
async function openConv(id, { focus = true } = {}) {
  id = Number(id);
  if (!state.convs.some((c) => c.id === id)) await loadConvs();
  if (!state.convs.some((c) => c.id === id)) throw new Error("Conversation introuvable.");
  state.active = id;
  state.replyTo = null; $("reply-bar").hidden = true;
  $("msg-search").value = ""; $("msg-search-bar").hidden = true;
  $("typing-hint").hidden = true;
  showChat(true); renderChatHeader(); renderConvs();
  $("chat-msgs").innerHTML = `<p class="msgs-loading">Chargement des messages…</p>`;
  let msgs;
  try { msgs = await api(`/api/messages/${id}`); }
  catch (e) { $("chat-msgs").innerHTML = `<p class="msgs-loading">Impossible de charger les messages : ${esc(e.message)}</p>`; throw e; }
  if (state.active !== id) return;
  state.messages = msgs;
  renderMessages();
  if (focus) { const fc = () => { if (!$("chat").hidden) $("chat-input").focus(); }; fc(); requestAnimationFrame(fc); setTimeout(fc, 80); } // Firefox rend le focus au bouton d’origine à la fermeture du dialog
  markRead();
  if (K) {
    try { await K.prepare(currentConv(), state.settings); } catch { /* ignore */ }
    if (state.active === id) { renderMessages({ keepScroll: true }); updateSecretBar(); }
  } else updateSecretBar();
}
function markRead() {
  const c = currentConv();
  const last = [...state.messages].reverse().find((m) => m.sender_id !== meId && m.id > 0);
  if (c) c.unread = 0;
  renderConvs();
  if (!last) return;
  if (!sendWs({ type: "receipt", message_id: last.id, status: "read" })) {
    api(`/api/messages/${last.id}/read`, { method: "POST", body: {} }).catch(() => {});
  }
}
async function startDm(userId) {
  userId = Number(userId);
  const u = state.members.find((x) => x.id === userId);
  closeDialog($("newmsg-dlg"));
  const conv = await api("/api/conversations/dm", { method: "POST", body: { user_id: userId } });
  if (!state.convs.some((c) => c.id === conv.id)) await loadConvs();
  state.tab = "chats"; switchTabSilently("chats");
  await openConv(conv.id);
  if (u) $("chat-input").placeholder = `Écrire à ${u.display_name || u.username}…`;
}
function switchTabSilently(tab) {
  for (const t of ["chats", "rooms", "people", "requests"]) {
    $("tab-" + t).setAttribute("aria-selected", String(t === tab));
    $("tab-" + t).classList.toggle("active", t === tab);
    $("pane-" + t).hidden = t !== tab;
  }
  renderConvs();
}
async function openGeneral() {
  let c = state.convs.find((x) => x.kind === "room" && x.slug === "general");
  if (!c) {
    const rooms = await api("/api/rooms");
    const g = rooms.find((r) => r.slug === "general");
    if (!g) throw new Error("Le salon #général n'existe pas.");
    await api(`/api/rooms/${g.id}/join`, { method: "POST", body: {} });
    await loadConvs();
    c = state.convs.find((x) => x.id === g.id);
  }
  switchTabSilently("chats"); state.tab = "chats";
  await openConv(c.id);
}
async function openNewMessage() {
  const dlg = $("newmsg-dlg");
  $("newmsg-search").value = "";
  state.pickIndex = 0;
  renderPicker();
  openDialog(dlg);
  setTimeout(() => $("newmsg-search").focus(), 30);
  try { await loadMembers(); } catch (e) { toast("Liste des membres indisponible : " + e.message); }
}

/* ---------- Envoi ---------- */
function keyErrorText(err) {
  if (err === "password_needed") return "Saisissez d'abord le code partagé de cette conversation.";
  if (err === "peer_key_missing") return "Votre correspondant ne s'est pas encore connecté : réessayez après sa première connexion.";
  return "Conversation en cours de préparation, réessayez dans un instant.";
}
async function conversationKey(conv) {
  await cryptoReady;
  if (!K) throw new Error("Module de sécurité indisponible : rechargez la page (Ctrl+Maj+R).");
  const key = await K.getConversationKey(conv, state.settings);
  if (key.error) { updateSecretBar(key.error); throw new Error(keyErrorText(key.error)); }
  return key;
}
async function sendCurrent() {
  const input = $("chat-input");
  const text = input.value.trim();
  const file = state.pendingFile;
  const conv = currentConv();
  if (!conv) { toast("Choisissez d'abord une conversation."); return; }
  if (!text && !file) { input.focus(); input.classList.add("shake"); setTimeout(() => input.classList.remove("shake"), 400); return; }
  const algo = state.settings.algo || "Aucun";
  let key = { keyHex: "", fp: "" };
  if (algo !== "Aucun" || file) key = await conversationKey(conv);
  if (text) {
    const enc = encodeText(text, algo, key.keyHex);
    const cid = clientId();
    state.meta.set(cid, { ...enc.meta, plain: text });
    const frame = {
      type: "chat.send", conversation_id: conv.id, algo: enc.algo, mode: enc.mode, iv: enc.iv,
      ciphertext: enc.ciphertext, tag: enc.tag, key_dist: state.settings.key_distribution || "broadcast",
      key_fp: key.fp, reply_to: state.replyTo, client_id: cid,
    };
    state.messages.push({ ...frame, type: undefined, id: -Date.now(), sender_id: meId, sender_name: "Vous",
      created_at: new Date().toISOString(), status: "sending" });
    input.value = ""; autosize();
    state.replyTo = null; $("reply-bar").hidden = true;
    renderMessages();
    stopTyping();
    await deliverFrame(frame);
  }
  if (file) { clearFile(); await sendAttachment(file, key, conv); }
  input.focus();
}
/** WebSocket si ouvert, sinon API REST (le serveur relaie en temps réel dans les deux cas). */
async function deliverFrame(frame) {
  if (sendWs(frame)) {
    setTimeout(() => {
      const m = state.messages.find((x) => x.client_id === frame.client_id);
      if (m && m.status === "sending") { m.status = "failed"; m._frame = frame; renderMessages({ keepScroll: true });
        toast("Le serveur n'a pas confirmé l'envoi. Touchez « réessayer »."); }
    }, 10000);
    return;
  }
  try {
    const { type, conversation_id, ...body } = frame;
    const msg = await api(`/api/messages/${conversation_id}`, { method: "POST", body });
    onFrame({ ...msg, type: "chat.message", client_id: frame.client_id });
  } catch (err) {
    const m = state.messages.find((x) => x.client_id === frame.client_id);
    if (m) { m.status = "failed"; m._frame = frame; renderMessages({ keepScroll: true }); }
    toast("Message non envoyé : " + err.message);
  }
}
async function sendAttachment(file, key, conv) {
  const buf = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < buf.length; i += 0x8000) binary += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  const meta = JSON.stringify({ name: file.name, mime: file.type || "application/octet-stream", data_b64: btoa(binary) });
  const fileEnc = C.encrypt(meta, "AES-GCM", key.keyHex);
  const label = "📎 " + file.name;
  const marker = C.encrypt(label, "AES-GCM", key.keyHex);
  const cid = clientId();
  state.meta.set(cid, { ...marker.meta, plain: label });
  const frame = { type: "chat.send", conversation_id: conv.id, algo: marker.algo, mode: marker.mode, iv: marker.iv,
    ciphertext: marker.ciphertext, tag: marker.tag, key_dist: state.settings.key_distribution, key_fp: key.fp,
    reply_to: null, client_id: cid, attachment: { iv: fileEnc.iv, ciphertext: fileEnc.ciphertext, tag: fileEnc.tag } };
  state.messages.push({ ...frame, type: undefined, attachment: null, id: -Date.now(), sender_id: meId,
    created_at: new Date().toISOString(), status: "sending" });
  renderMessages();
  await deliverFrame(frame);
}
function clearFile() {
  state.pendingFile = null; $("file-input").value = ""; $("file-chip").hidden = true;
}
function autosize() {
  const i = $("chat-input");
  i.style.height = "auto";
  i.style.height = Math.min(i.scrollHeight, 160) + "px";
}
function stopTyping() {
  clearTimeout(state.typingTimer);
  if (state.typing && state.active) sendWs({ type: "typing", conversation_id: state.active, active: false });
  state.typing = false;
}

/* ---------- Temps réel (WebSocket) ---------- */
let ws = null, reconnectDelay = 1000, wsEverOpened = false;
function connectWs() {
  setConn(wsEverOpened ? "offline" : "connecting");
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  try { ws = new WebSocket(`${proto}//${location.host}/ws`); }
  catch (e) { setTimeout(connectWs, reconnectDelay); return; }
  ws.addEventListener("open", () => {
    const resync = wsEverOpened;
    wsEverOpened = true; reconnectDelay = 1000; setConn("online");
    if (resync) {
      loadConvs().then(() => { if (state.active) openConv(state.active, { focus: false }); }).catch(() => {});
      loadMembers().catch(() => {});
    }
  });
  ws.addEventListener("message", (ev) => {
    let f; try { f = JSON.parse(ev.data); } catch { return; }
    try { onFrame(f); } catch (e) { console.error("Trame non traitée", f, e); }
  });
  ws.addEventListener("close", (ev) => {
    setConn(wsEverOpened ? "offline" : "connecting");
    if (ev.code === 4401) { toast("Votre session a expiré : reconnectez-vous."); setTimeout(() => (location.href = "/connexion"), 1500); return; }
    setTimeout(connectWs, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.6, 10000);
  });
}
function sendWs(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(obj)); return true; }
  return false;
}
window.addEventListener("online", () => { if (!ws || ws.readyState > 1) connectWs(); });

function onFrame(f) {
  switch (f.type) {
    case "error": {
      if (f.code === "key_missing") break;
      const m = f.client_id && state.messages.find((x) => x.client_id === f.client_id);
      if (m) { m.status = "failed"; renderMessages({ keepScroll: true }); }
      toast(f.message || "Une erreur est survenue.");
      break;
    }
    case "presence.list":
      state.online = new Set(f.online || []);
      renderConvs(); renderMembersEverywhere(); if (state.active) renderChatHeader();
      break;
    case "presence":
      if (f.online) state.online.add(f.user_id); else state.online.delete(f.user_id);
      if (f.online && !state.members.some((u) => u.id === f.user_id) && f.user_id !== meId) loadMembers().catch(() => {});
      renderConvs(); renderMembersEverywhere(); if (state.active) renderChatHeader();
      break;
    case "chat.message": onChatMessage(f); break;
    case "typing":
      if (f.conversation_id === state.active && f.user_id !== meId) {
        const u = state.members.find((x) => x.id === f.user_id);
        const el = $("typing-hint");
        el.hidden = !f.active;
        el.textContent = f.active ? `${u?.display_name || u?.username || "Quelqu'un"} écrit…` : "";
        clearTimeout(state.typingHideTimer);
        if (f.active) state.typingHideTimer = setTimeout(() => { el.hidden = true; }, 6000);
      }
      break;
    case "receipt":
      if (f.conversation_id === state.active) {
        for (const m of state.messages) {
          if (m.sender_id === meId && m.id > 0 && m.id <= f.message_id && f.status === "read") m.status = "read";
          else if (m.id === f.message_id && m.status !== "read") m.status = f.status;
        }
        renderMessages({ keepScroll: true });
      }
      break;
    case "chat.edited":
      if (f.conversation_id === state.active) {
        state.meta.delete(f.id);
        const i = state.messages.findIndex((m) => m.id === f.id);
        if (i >= 0) state.messages[i] = { ...state.messages[i], ...f }; else state.messages.push(f);
        renderMessages({ keepScroll: true });
      }
      break;
    case "chat.deleted":
      if (f.conversation_id === state.active) {
        const m = state.messages.find((x) => x.id === f.id);
        if (m) { m.deleted = true; renderMessages({ keepScroll: true }); }
      }
      break;
    case "chat.reaction":
      if (f.conversation_id === state.active) {
        const m = state.messages.find((x) => x.id === f.message_id);
        if (m) { m.reactions = f.reactions; renderMessages({ keepScroll: true }); }
      }
      break;
    case "demo.settings":
      state.settings = f; updateAlgoBadge();
      refreshKeys();
      break;
    case "key.public":
      if (K) { K.setPeerPublic(f.user_id, f.public_key_hex); refreshKeys(); }
      break;
    case "group.key":
      if (K) K.unwrapGroupKey(f).then(() => refreshKeys()).catch(() => {});
      break;
    case "conv.created": case "conv.member":
      loadConvs().catch(() => {});
      break;
    case "contact.request":
      loadContacts().catch(() => {});
      toast("Nouvelle demande de contact (onglet Demandes).", "ok");
      break;
    case "contact.update":
      loadContacts().catch(() => {});
      if (f.status === "accepted") toast("Votre demande de contact a été acceptée.", "ok");
      break;
    case "read.sync": {
      const c = state.convs.find((x) => x.id === f.conversation_id);
      if (c) { c.unread = 0; renderConvs(); }
      break;
    }
  }
}

function onChatMessage(f) {
  let c = state.convs.find((x) => x.id === f.conversation_id);
  if (!c) { loadConvs().then(() => onChatMessage(f)).catch(() => {}); return; }
  c.last_message = f; c.updated_at = f.created_at;
  state.convs.sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
  if (f.conversation_id === state.active) {
    const idx = f.client_id ? state.messages.findIndex((m) => m.client_id === f.client_id) : -1;
    if (idx >= 0) {
      const meta = state.meta.get(f.client_id);
      if (meta) state.meta.set(f.id, meta);
      state.messages[idx] = { ...f, status: f.status || "sent" };
    } else if (!state.messages.some((m) => m.id === f.id)) state.messages.push(f);
    renderMessages({ keepScroll: f.sender_id !== meId });
    if (f.sender_id !== meId) {
      document.getElementById("typing-hint").hidden = true;
      const st = document.visibilityState === "visible" ? "read" : "delivered";
      sendWs({ type: "receipt", message_id: f.id, status: st });
      if (st !== "read") c.unread = (c.unread || 0) + 1;
    }
  } else if (f.sender_id !== meId) {
    c.unread = (c.unread || 0) + 1;
    sendWs({ type: "receipt", message_id: f.id, status: "delivered" });
    playNotify();
  }
  renderConvs();
}
function playNotify() {
  const a = document.getElementById("notify-sound");
  if (!a || typeof a.play !== "function") return;
  const p = a.play();
  if (p && p.catch) p.catch(() => {});
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && state.active) markRead();
});

async function refreshKeys() {
  const c = currentConv();
  if (K && c) { try { await K.prepare(c, state.settings); } catch { /* ignore */ } }
  updateSecretBar();
  if (state.active) renderMessages({ keepScroll: true });
  renderConvs();
}
/* Barre « code partagé » (mode password) et avis (mode x25519) — texte neutre. */
async function updateSecretBar(error) {
  const bar = $("conv-secret"), form = $("conv-secret-form"), msg = $("conv-secret-msg");
  const c = currentConv();
  const mode = state.settings.key_distribution;
  if (!c || state.settings.algo === "Aucun" || mode === "broadcast" || !K) { bar.hidden = true; return; }
  const k = error ? { error } : await K.getConversationKey(c, state.settings, mode, { create: false });
  if (!k.error || (k.error === "group_key_missing" && !error)) { bar.hidden = true; return; }
  bar.hidden = false;
  form.hidden = k.error !== "password_needed";
  msg.textContent = k.error === "password_needed"
    ? "Saisissez le code partagé de cette conversation (convenu avec votre correspondant). Il doit saisir le même code de son côté."
    : k.error === "peer_key_missing"
      ? "Votre correspondant ne s'est pas encore connecté depuis son appareil. Vous pourrez lui écrire dès sa prochaine connexion (vérification automatique)."
      : "Conversation en cours de préparation… nouvel essai automatique.";
  if (k.error !== "password_needed") {
    if (c.other?.id) sendWs({ type: "key.request", user_id: c.other.id });
    clearTimeout(state.keyRetry);
    state.keyRetry = setTimeout(() => { K.forgetPeer?.(c.other?.id); refreshKeys(); }, 8000);
  }
}

/* ---------- Actions sur un message ---------- */
const msgOf = (el) => state.messages.find((m) => String(m.id) === el.closest(".bubble")?.dataset.mid);
async function reactTo(m, emoji) {
  const r = await api(`/api/messages/${m.id}/reactions`, { method: "POST", body: { emoji } });
  m.reactions = r.reactions;
  renderMessages({ keepScroll: true });
}
async function editMessage(m) {
  const dec = decode(m);
  if (!dec.ok) throw new Error("Ce message ne peut pas être modifié sur cet appareil.");
  const next = await ask({ title: "Modifier le message", input: true, value: dec.plain, okLabel: "Enregistrer" });
  if (next == null || !next.trim() || next.trim() === dec.plain) return;
  const algo = state.settings.algo || "Aucun";
  const key = algo === "Aucun" ? { keyHex: "", fp: "" } : await conversationKey(currentConv());
  const enc = encodeText(next.trim(), algo, key.keyHex);
  const payload = await api(`/api/messages/${m.id}`, { method: "PATCH", body: {
    algo: enc.algo, mode: enc.mode, iv: enc.iv, ciphertext: enc.ciphertext, tag: enc.tag,
    key_dist: state.settings.key_distribution, key_fp: key.fp } });
  Object.assign(m, payload);
  state.meta.set(m.id, { ...enc.meta, plain: next.trim() });
  renderMessages({ keepScroll: true });
  ok("Message modifié.");
}
async function deleteMessage(m) {
  const yes = await ask({ title: "Supprimer ce message ?", text: "Il sera remplacé par « Message supprimé » pour tout le monde.", okLabel: "Supprimer", danger: true });
  if (!yes) return;
  await api(`/api/messages/${m.id}`, { method: "DELETE" });
  m.deleted = true;
  renderMessages({ keepScroll: true });
  ok("Message supprimé.");
}
async function reportMessage(m) {
  const reason = await ask({ title: "Signaler ce message", text: "Expliquez brièvement le problème à l'équipe de modération.", input: true, okLabel: "Envoyer" });
  if (!reason || !reason.trim()) return;
  await api("/api/reports", { method: "POST", body: { target_type: "message", target_id: m.id, reason: reason.trim() } });
  ok("Signalement envoyé. Merci !");
}
async function openAttachment(el, m) {
  const att = await api(`/api/attachments/${el.dataset.att}`);
  await cryptoReady;
  if (!K) throw new Error("Module de sécurité indisponible.");
  const keyHex = K.keyForMessage({ ...att, key_fp: m.key_fp, algo: att.algo }, state.settings);
  if (keyHex === null) throw new Error("Fichier illisible sur cet appareil.");
  const dec = C.decrypt({ algo: att.algo, mode: "GCM", iv: att.iv, ciphertext: att.ciphertext, tag: att.tag }, keyHex);
  if (!dec.ok) throw new Error("Fichier illisible : " + dec.error);
  const meta = JSON.parse(dec.plain);
  const bin = Uint8Array.from(atob(meta.data_b64), (ch) => ch.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bin], { type: meta.mime }));
  if ((meta.mime || "").startsWith("image/")) {
    el.outerHTML = `<img class="att-img" src="${url}" alt="${esc(meta.name || "")}">`;
  } else {
    const a = document.createElement("a");
    a.href = url; a.download = meta.name || "fichier";
    document.body.appendChild(a); a.click(); a.remove();
    ok("Téléchargement : " + (meta.name || "fichier"));
  }
}

/* ---------- Membres, salons, contacts, groupes ---------- */
const memberName = (id) => { const u = state.members.find((x) => x.id === Number(id)); return u ? (u.display_name || u.username) : "ce membre"; };
async function addContact(id) {
  const r = await api("/api/contacts/request", { method: "POST", body: { user_id: Number(id) } });
  ok(r.status === "accepted" ? `${memberName(id)} fait déjà partie de vos contacts.` : `Demande de contact envoyée à ${memberName(id)}.`);
  loadContacts().catch(() => {});
}
async function blockMember(id) {
  const yes = await ask({ title: `Bloquer ${memberName(id)} ?`, text: "Vous ne recevrez plus ses messages privés.", okLabel: "Bloquer", danger: true });
  if (!yes) return;
  await api(`/api/contacts/${id}/block`, { method: "POST", body: {} });
  ok(`${memberName(id)} est bloqué.`);
  loadContacts().catch(() => {});
}
async function roomOpen(id) {
  id = Number(id);
  const joined = state.convs.some((c) => c.id === id);
  if (!joined) {
    await api(`/api/rooms/${id}/join`, { method: "POST", body: {} });
    await loadConvs();
    const conv = state.convs.find((c) => c.id === id);
    if (conv && state.settings.key_distribution === "x25519" && K) {
      try { await K.distributeGroupKey(conv, conv.member_ids || []); } catch { /* clé créée au premier envoi */ }
    }
    ok(`Vous avez rejoint ${conv?.title || "le salon"}.`);
    loadRooms().catch(() => {});
  }
  await openConv(id);
}
async function roomLeave(id) {
  id = Number(id);
  const r = state.rooms.find((x) => x.id === id);
  const yes = await ask({ title: `Quitter ${r?.title || "ce salon"} ?`, text: "Vous pourrez le rejoindre à nouveau quand vous voulez.", okLabel: "Quitter", danger: true });
  if (!yes) return;
  await api(`/api/rooms/${id}/leave`, { method: "POST", body: {} });
  if (state.active === id) { state.active = null; showChat(false); }
  await loadConvs(); await loadRooms();
  ok(`Vous avez quitté ${r?.title || "le salon"}.`);
}
async function contactAction(act, cid) {
  const url = act === "req-accept" ? `/api/contacts/${cid}/accept` : act === "req-refuse" ? `/api/contacts/${cid}/refuse` : `/api/contacts/${cid}`;
  await api(url, { method: act === "req-remove" ? "DELETE" : "POST", body: act === "req-remove" ? undefined : {} });
  ok(act === "req-accept" ? "Contact ajouté." : act === "req-refuse" ? "Demande refusée." : "C'est fait.");
  await loadContacts();
}
async function openGroupDialog() {
  state.groupSel = new Set();
  $("group-name").value = ""; $("group-search").value = "";
  renderGroupPicker();
  openDialog($("group-dlg"));
  setTimeout(() => $("group-name").focus(), 30);
  loadMembers().catch(() => {});
}
async function createGroup() {
  const title = $("group-name").value.trim();
  if (!title) { $("group-name").focus(); throw new Error("Donnez un nom au groupe."); }
  if (!state.groupSel.size) throw new Error("Sélectionnez au moins un membre.");
  const member_ids = [...state.groupSel];
  const g = await api("/api/groups", { method: "POST", body: { title, member_ids } });
  closeDialog($("group-dlg"));
  await loadConvs();
  const conv = state.convs.find((c) => c.id === g.id);
  if (conv && state.settings.key_distribution === "x25519" && K) {
    try { await K.distributeGroupKey(conv, conv.member_ids || member_ids); } catch { /* clé créée au premier envoi */ }
  }
  switchTabSilently("chats"); state.tab = "chats";
  await openConv(g.id);
  ok(`Groupe « ${title} » créé.`);
}
async function openSettings() {
  openDialog($("settings-dlg"));
  $("settings-msg").hidden = true;
  try {
    const me = await api("/api/users/me");
    const f = $("settings-form");
    f.display_name.value = me.display_name || "";
    f.bio.value = me.bio || "";
    f.domain.value = me.domain || "autre";
    f.skills.value = (me.skills || []).join(", ");
    f.github.value = (me.links || []).find((l) => l.kind === "github")?.url || "";
    f.portfolio.value = (me.links || []).find((l) => l.kind === "portfolio")?.url || "";
  } catch (e) { toast("Profil indisponible : " + e.message); }
}
async function saveSettings() {
  const f = $("settings-form"), msg = $("settings-msg");
  const btn = f.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    await api("/api/users/me", { method: "PATCH", body: { display_name: f.display_name.value, bio: f.bio.value, domain: f.domain.value } });
    const skills = f.skills.value.split(",").map((s) => s.trim()).filter(Boolean);
    await api("/api/account/skills", { method: "PUT", body: { skills } });
    await api("/api/account/links", { method: "PUT", body: { github: f.github.value, portfolio: f.portfolio.value } });
    if (f.avatar.files[0]) {
      const fd = new FormData();
      fd.append("file", f.avatar.files[0]);
      const r = await fetch("/api/account/avatar", { method: "POST", body: fd, credentials: "same-origin",
        headers: { "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content } });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || "Photo refusée.");
    }
    if (f.current.value && f.new_password.value) {
      await api("/api/account/password", { method: "POST", body: { current: f.current.value, new_password: f.new_password.value } });
      f.current.value = ""; f.new_password.value = "";
    }
    msg.hidden = false; msg.className = "form-msg ok"; msg.textContent = "Profil enregistré.";
    ok("Profil enregistré.");
  } catch (err) {
    msg.hidden = false; msg.className = "form-msg error"; msg.textContent = err.message;
    toast(err.message);
  } finally { btn.disabled = false; }
}
async function deleteAccount() {
  const yes = await ask({ title: "Supprimer définitivement votre compte ?", text: "Cette action est irréversible.", okLabel: "Supprimer mon compte", danger: true });
  if (!yes) return;
  await api("/api/account", { method: "DELETE" });
  location.href = "/";
}

/* ---------- Table des actions (délégation d'événements) ---------- */
const ACTIONS = {
  "tab": (el) => switchTab(el.dataset.tab),
  "new-message": () => openNewMessage(),
  "open-general": () => openGeneral(),
  "open-conv": (el) => openConv(el.dataset.convId),
  "dm": (el) => startDm(el.dataset.userId),
  "contact-add": (el) => addContact(el.dataset.userId),
  "block": (el) => blockMember(el.dataset.userId),
  "room-open": (el) => roomOpen(el.dataset.roomId),
  "room-leave": (el) => roomLeave(el.dataset.roomId),
  "req-accept": (el) => contactAction("req-accept", el.dataset.contactId),
  "req-refuse": (el) => contactAction("req-refuse", el.dataset.contactId),
  "req-remove": (el) => contactAction("req-remove", el.dataset.contactId),
  "new-group": () => openGroupDialog(),
  "group-toggle": (el) => {
    const id = Number(el.dataset.userId);
    if (state.groupSel.has(id)) state.groupSel.delete(id); else state.groupSel.add(id);
    renderGroupPicker();
  },
  "open-settings": () => openSettings(),
  "delete-account": () => deleteAccount(),
  "close-dialog": (el) => closeDialog(el.closest("dialog")),
  "ask-cancel": () => finishAsk(null),
  "back": () => { state.active = null; showChat(false); renderConvs(); },
  "toggle-search": () => {
    const bar = $("msg-search-bar");
    bar.hidden = !bar.hidden;
    if (!bar.hidden) $("msg-search").focus(); else { $("msg-search").value = ""; applyMsgSearch(); }
  },
  "cancel-reply": () => { state.replyTo = null; $("reply-bar").hidden = true; $("chat-input").focus(); },
  "clear-file": () => { clearFile(); toast("Fichier retiré.", "ok"); },
  "attach": () => $("file-input").click(),
  "toggle-emoji": () => { const p = $("emoji-pal"); p.hidden = !p.hidden; },
  "insert-emoji": (el) => {
    const i = $("chat-input"), e = el.dataset.emoji;
    const s = i.selectionStart ?? i.value.length, t = i.selectionEnd ?? i.value.length;
    i.value = i.value.slice(0, s) + e + i.value.slice(t);
    i.focus(); i.selectionStart = i.selectionEnd = s + e.length;
    $("emoji-pal").hidden = true; autosize();
  },
  "reply": (el) => {
    const m = msgOf(el); if (!m) return;
    state.replyTo = m.id;
    const d = decode(m);
    $("reply-preview").textContent = "Réponse à : " + (d.ok ? d.plain.slice(0, 80) : "message");
    $("reply-bar").hidden = false; $("chat-input").focus();
  },
  "react-pick": (el) => {
    const pal = el.closest(".bubble").querySelector(".react-pal");
    document.querySelectorAll(".react-pal").forEach((p) => { if (p !== pal) p.hidden = true; });
    pal.hidden = !pal.hidden;
  },
  "react": (el) => { const m = msgOf(el); if (m) return reactTo(m, el.dataset.emoji); },
  "edit": (el) => { const m = msgOf(el); if (m) return editMessage(m); },
  "delete": (el) => { const m = msgOf(el); if (m) return deleteMessage(m); },
  "report": (el) => { const m = msgOf(el); if (m) return reportMessage(m); },
  "retry": (el) => {
    const m = msgOf(el); if (!m) return;
    const fr = m._frame || { type: "chat.send", conversation_id: m.conversation_id, algo: m.algo, mode: m.mode, iv: m.iv,
      ciphertext: m.ciphertext, tag: m.tag, key_dist: m.key_dist, key_fp: m.key_fp, reply_to: m.reply_to, client_id: m.client_id };
    m.status = "sending"; renderMessages({ keepScroll: true });
    return deliverFrame(fr);
  },
  "att-open": (el) => { const m = msgOf(el); if (m) return openAttachment(el, m); },
};
const busy = new WeakSet();
/* Une liste peut être redessinée (présence, accusés…) entre l'appui et le relâchement :
   le navigateur perd alors le « click ». On mémorise la cible de l'appui pour le rejouer. */
let press = null;
root.addEventListener("pointerdown", (e) => {
  const el = e.target.closest?.("[data-action]");
  press = el && root.contains(el) ? { el, data: { ...el.dataset }, t: Date.now() } : null;
}, true);
function recoverPressed() {
  if (!press || press.el.isConnected || Date.now() - press.t > 1500) return null;
  const same = [...root.querySelectorAll(`[data-action="${CSS.escape(press.data.action)}"]`)]
    .find((x) => Object.entries(press.data).every(([k, v]) => x.dataset[k] === v));
  return same || press.el;
}
root.addEventListener("click", (e) => {
  const rec = e.target.closest("[data-action]") ? null : recoverPressed();
  const el = e.target.closest("[data-action]") || rec;
  press = null;
  if (!el || (!root.contains(el) && el !== rec)) {
    // Clic ailleurs : fermer les petites palettes ouvertes ; tap sur une bulle = afficher ses actions.
    if (!e.target.closest(".emoji-pal")) $("emoji-pal").hidden = true;
    const b = e.target.closest(".bubble");
    document.querySelectorAll(".bubble.show-actions").forEach((x) => { if (x !== b) x.classList.remove("show-actions"); });
    if (b && !e.target.closest("a, details, summary")) b.classList.toggle("show-actions");
    return;
  }
  const fn = ACTIONS[el.dataset.action];
  if (!fn) return;
  e.preventDefault();
  if (busy.has(el)) return;
  busy.add(el); el.classList.add("is-busy");
  Promise.resolve().then(() => fn(el, e))
    .catch((err) => toast(err?.message || String(err)))
    .finally(() => { busy.delete(el); el.classList.remove("is-busy"); });
});

/* ---------- Champs, formulaires, clavier ---------- */
root.addEventListener("mousedown", (e) => {
  if (e.target.tagName === "DIALOG") { // clic sur le fond assombri
    if (e.target.id === "ask-dlg") finishAsk(null); else closeDialog(e.target);
  }
});
$("ask-dlg").addEventListener("close", () => { if (askResolve) finishAsk(null); });
$("ask-form").addEventListener("submit", (e) => {
  e.preventDefault();
  finishAsk($("ask-input").hidden ? true : $("ask-input").value);
});
$("ask-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); finishAsk($("ask-input").value); }
});
$("newmsg-search").addEventListener("input", () => { state.pickIndex = 0; renderPicker(); });
$("newmsg-search").addEventListener("keydown", (e) => {
  const rows = [...$("newmsg-list").querySelectorAll(".member-row")];
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    state.pickIndex = Math.max(0, Math.min(rows.length - 1, state.pickIndex + (e.key === "ArrowDown" ? 1 : -1)));
    rows.forEach((b, i) => b.classList.toggle("kbd", i === state.pickIndex));
    rows[state.pickIndex]?.scrollIntoView({ block: "nearest" });
  } else if (e.key === "Enter") {
    e.preventDefault();
    const row = rows[state.pickIndex] || rows[0];
    if (row) startDm(row.dataset.userId).catch((err) => toast(err.message));
  }
});
$("people-search").addEventListener("input", renderPeople);
$("group-search").addEventListener("input", renderGroupPicker);
$("group-form").addEventListener("submit", (e) => { e.preventDefault(); createGroup().catch((err) => toast(err.message)); });
$("settings-form").addEventListener("submit", (e) => { e.preventDefault(); saveSettings(); });
$("msg-search").addEventListener("input", applyMsgSearch);
const secretForm = $("conv-secret-form");
secretForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  await cryptoReady;
  const pwd = secretForm.querySelector("input").value;
  if (!pwd) return;
  await K.setConversationPassword(currentConv(), pwd);
  secretForm.reset();
  await refreshKeys();
});

const input = $("chat-input");
$("chat-form").addEventListener("submit", (e) => { e.preventDefault(); sendCurrent().catch((err) => toast(err.message)); });
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
    e.preventDefault();
    sendCurrent().catch((err) => toast(err.message));
  }
});
input.addEventListener("input", () => {
  autosize();
  if (!state.active) return;
  if (!state.typing) { state.typing = true; sendWs({ type: "typing", conversation_id: state.active, active: true }); }
  clearTimeout(state.typingTimer);
  state.typingTimer = setTimeout(stopTyping, 1500);
});
$("file-input").addEventListener("change", () => {
  const f = $("file-input").files?.[0];
  if (!f) return;
  if (f.size > 700_000) { clearFile(); toast("Fichier trop volumineux (700 Ko maximum)."); return; }
  state.pendingFile = f;
  $("file-name").textContent = `📎 ${f.name} (${Math.ceil(f.size / 1024)} Ko) — sera envoyé avec « Envoyer »`;
  $("file-chip").hidden = false;
  input.focus();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !document.querySelector("dialog[open]")) {
    $("emoji-pal").hidden = true;
    if (state.replyTo) { state.replyTo = null; $("reply-bar").hidden = true; }
  }
});

/* ---------- Démarrage ---------- */
switchTabSilently("chats");
showChat(false);
renderConvs(); renderOnline(); renderRequests();
window.__kernelReady = true; // les boutons sont opérationnels dès maintenant
window.KernelApp = { state, get ws() { return ws; } }; // aide au diagnostic et aux tests e2e
(async () => {
  await loadSettings();
  const results = await Promise.allSettled([loadConvs(), loadMembers(), loadContacts()]);
  const failed = results.filter((r) => r.status === "rejected");
  if (failed.length) toast("Certaines données n'ont pas pu être chargées : " + failed[0].reason.message);
  connectWs();
  root.dataset.ready = "1";
  await cryptoReady;
  renderConvs();
  if (state.active) refreshKeys();
})();
