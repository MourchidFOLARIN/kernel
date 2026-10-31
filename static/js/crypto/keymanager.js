/**
 * Abstraction unique : getConversationKey(conv, settings[, mode]).
 *
 *   broadcast → settings.broadcast_key_hex (diffusée en clair par le serveur)
 *   password  → PBKDF2(mot de passe saisi, sel public de la conversation)
 *   x25519    → SHA-256(X25519(ma privée, publique du correspondant))
 *
 * Chaque clé obtenue est mémorisée par empreinte (IndexedDB "keys"), ce qui permet
 * de relire l'historique envoyé avec une ancienne clé / un autre mode, tant que l'on
 * reste sur le même navigateur.
 */
import { api } from "../api.js";
import { decrypt as cryptoDecrypt, encrypt as cryptoEncrypt } from "./index.js";
import { derivePasswordKey, fingerprint, generateX25519, x25519SessionKey } from "./keys.js";
import { idbAll, idbGet, idbSet } from "./keystore.js";

const byFp = new Map();      // empreinte → clé hex
const peerPubs = new Map();  // user_id → clé publique hex
let identity = null;         // { privateKeyHex, publicKeyHex }

export async function init() {
  for (const [fp, k] of await idbAll("keys")) byFp.set(fp, k);
  identity = await idbGet("identity", "x25519");
  if (!identity) {
    identity = generateX25519();
    await idbSet("identity", "x25519", identity);
  }
  // Republie à chaque démarrage : si IndexedDB a été vidé, la nouvelle clé remplace
  // l'ancienne côté serveur → l'historique x25519 précédent devient illisible ici.
  await api("/api/keys/public", { method: "POST", body: { public_key_hex: identity.publicKeyHex } });
  return identity;
}

export function myPublicKey() { return identity?.publicKeyHex || ""; }

export function setPeerPublic(userId, pubHex) { peerPubs.set(Number(userId), pubHex); }
export function forgetPeer(userId) { if (userId) peerPubs.delete(Number(userId)); }

async function remember(keyHex) {
  const fp = fingerprint(keyHex);
  if (!byFp.has(fp)) { byFp.set(fp, keyHex); await idbSet("keys", fp, keyHex); }
  return { keyHex, fp };
}

async function peerPublic(userId) {
  if (peerPubs.has(userId)) return peerPubs.get(userId);
  try {
    const r = await api(`/api/keys/public/${userId}`);
    peerPubs.set(userId, r.public_key_hex);
    return r.public_key_hex;
  } catch { return null; }
}

/** Retourne { keyHex, fp } ou { error: ... }. */
async function getConversationKeyBase(conv, settings, mode = settings?.key_distribution || "broadcast") {
  if (!conv) return { error: "no_conversation" };
  if (mode === "broadcast") {
    if (!settings?.broadcast_key_hex) return { error: "no_key" };
    return remember(settings.broadcast_key_hex);
  }
  if (mode === "password") {
    const k = await idbGet("convkeys", `password:${conv.id}`);
    return k ? remember(k) : { error: "password_needed" };
  }
  if (mode === "x25519") {
    const peerId = conv.other?.id;
    const pub = peerId ? await peerPublic(peerId) : null;
    if (!pub) return { error: "peer_key_missing" };
    return remember(x25519SessionKey(identity.privateKeyHex, pub));
  }
  return { error: "unknown_mode" };
}

/** Saisie du mot de passe commun : le sel vient du serveur, la clé reste ici. */
export async function setConversationPassword(conv, password) {
  const { salt } = await api(`/api/keys/salt/${conv.id}`);
  const keyHex = derivePasswordKey(password, salt);
  await idbSet("convkeys", `password:${conv.id}`, keyHex);
  return remember(keyHex);
}

/** Pré-calcule toutes les clés disponibles pour une conversation (pour l'historique). */
export async function prepare(conv, settings) {
  for (const m of ["broadcast", "password", "x25519"]) {
    try { await getConversationKey(conv, settings, m, { create: false }); } catch { /* ignore */ }
  }
}

/** Clé pour déchiffrer un message (synchrone, après prepare). null = indisponible. */
export function keyForMessage(msg, settings) {
  if (!msg.algo || msg.algo === "Aucun") return "";
  if (msg.key_fp) return byFp.get(msg.key_fp) ?? null;
  return settings?.broadcast_key_hex || null; // messages antérieurs à l'étape 4
}


/** Mode X25519 pour groupes/salons : crée une clé de groupe et l'emballe pour chaque membre. */
export async function distributeGroupKey(conv, memberIds) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const keyHex = Array.from(keyBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  const { fp } = await remember(keyHex);
  await idbSet("convkeys", `group:${conv.id}:${fp}`, keyHex);
  await idbSet("convkeys", `group:${conv.id}:current`, keyHex);
  for (const uid of memberIds) {
    if (uid === undefined) continue;
    const pub = await peerPublic(uid);
    if (!pub) continue;
    const wrapKey = x25519SessionKey(identity.privateKeyHex, pub);
    // Emballage : AES-GCM du keyHex (texte) avec la clé pair-à-pair.
    const enc = cryptoEncrypt(keyHex, "AES-GCM", wrapKey);
    await api("/api/group-keys", { method: "POST", body: {
      conversation_id: conv.id, key_fp: fp, recipient_id: uid,
      iv: enc.iv, ciphertext: enc.ciphertext, tag: enc.tag,
    }});
  }
  return { keyHex, fp };
}

export async function unwrapGroupKey(wrap) {
  // wrap: { sender_id, iv, ciphertext, tag, key_fp }
  const pub = await peerPublic(wrap.sender_id);
  if (!pub) return null;
  const wrapKey = x25519SessionKey(identity.privateKeyHex, pub);
  const dec = cryptoDecrypt({ algo: "AES-GCM", mode: "GCM", iv: wrap.iv,
                              ciphertext: wrap.ciphertext, tag: wrap.tag }, wrapKey);
  if (!dec.ok) return null;
  const keyHex = dec.plain; // le clair est la clé de groupe en hex
  await remember(keyHex);
  await idbSet("convkeys", `group:${wrap.conversation_id || ""}:${wrap.key_fp}`, keyHex);
  await idbSet("convkeys", `group:${wrap.conversation_id || ""}:current`, keyHex);
  return { keyHex, fp: wrap.key_fp };
}

export async function fetchGroupWraps(convId) {
  try {
    const wraps = await api(`/api/group-keys/${convId}`);
    for (const w of wraps) {
      w.conversation_id = convId;
      await unwrapGroupKey(w);
    }
  } catch { /* ignore */ }
}

/** Override getConversationKey pour groupes en x25519. */
export async function getConversationKey(conv, settings, mode = settings?.key_distribution || "broadcast", { create = true } = {}) {
  if (conv && (conv.kind === "group" || conv.kind === "room") && mode === "x25519") {
    const cur = await idbGet("convkeys", `group:${conv.id}:current`);
    if (cur) return remember(cur);
    await fetchGroupWraps(conv.id);
    const again = await idbGet("convkeys", `group:${conv.id}:current`);
    if (again) return remember(again);
    // Pas encore de clé : on en crée une et on la distribue (premier à écrire).
    if (create && conv.member_ids?.length) {
      return distributeGroupKey(conv, conv.member_ids);
    }
    return { error: "group_key_missing" };
  }
  return getConversationKeyBase(conv, settings, mode);
}
