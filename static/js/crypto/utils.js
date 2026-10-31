/** Utilitaires hex / aléas / PKCS#7 — partagés navigateur & Node. */

export function bytesToHex(bytes) {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  if (!hex) return new Uint8Array(0);
  if (hex.length % 2) throw new Error("hex impair");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

/** Aléas via Web Crypto (navigateur) ou crypto.getRandomValues polyfill Node. */
export function randomBytes(n) {
  const out = new Uint8Array(n);
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(out);
  } else {
    // Node < 19 fallback (ne devrait pas arriver avec Node 20+)
    const { randomFillSync } = awaitableNodeCrypto();
    randomFillSync(out);
  }
  return out;
}

function awaitableNodeCrypto() {
  // import synchrone impossible en ESM pur ; on utilise webcrypto Node.
  return globalThis.crypto;
}

export function pkcs7Pad(data, blockSize) {
  const pad = blockSize - (data.length % blockSize);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

export function pkcs7Unpad(data, blockSize) {
  if (!data.length || data.length % blockSize) throw new Error("bourrage invalide");
  const pad = data[data.length - 1];
  if (pad < 1 || pad > blockSize) throw new Error("bourrage invalide");
  for (let i = 0; i < pad; i++) {
    if (data[data.length - 1 - i] !== pad) throw new Error("bourrage invalide");
  }
  return data.slice(0, data.length - pad);
}

/** Tronque / étend une clé hex broadcast à `n` octets (répétition ou coupe). */
export function keyBytesFromHex(hex, n) {
  if (!hex) throw new Error("clé manquante");
  let raw = hexToBytes(hex);
  if (raw.length === 0) throw new Error("clé vide");
  if (raw.length === n) return raw;
  if (raw.length > n) return raw.slice(0, n);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = raw[i % raw.length];
  return out;
}

export function truncateKeyDisplay(hex, keep = 8) {
  if (!hex) return "—";
  if (hex.length <= keep * 2) return hex;
  return hex.slice(0, keep) + "…" + hex.slice(-keep);
}
