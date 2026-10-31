/** Conversions octets / hex / UTF-8 et aléa (crypto.getRandomValues). */
export function utf8ToBytes(s) { return new TextEncoder().encode(s); }
export function bytesToUtf8(b) { return new TextDecoder("utf-8", { fatal: false }).decode(b); }
export function bytesToHex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
export function hexToBytes(h) {
  if (!h) return new Uint8Array(0);
  if (h.length % 2 || /[^0-9a-f]/i.test(h)) throw new Error("hex invalide");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
/** forge travaille en « chaînes binaires » (1 char = 1 octet). */
export function bytesToBin(b) { let s = ""; for (const x of b) s += String.fromCharCode(x); return s; }
export function binToBytes(s) { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 0xff; return b; }
