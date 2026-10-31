/**
 * Algorithmes classiques écrits à la main : César, Vigenère, XOR, RC4.
 * (RC4 : KSA/PRGA minimal — documenté ; aucun autre algo réimplémenté.)
 */
import { bytesToHex, bytesToUtf8, hexToBytes, utf8ToBytes } from "./utils.js";

export function caesarEncrypt(plain, shift) {
  const s = ((shift % 26) + 26) % 26;
  return [...plain].map((ch) => {
    const c = ch.codePointAt(0);
    if (c >= 65 && c <= 90) return String.fromCodePoint(((c - 65 + s) % 26) + 65);
    if (c >= 97 && c <= 122) return String.fromCodePoint(((c - 97 + s) % 26) + 97);
    return ch;
  }).join("");
}

export function caesarDecrypt(cipher, shift) {
  return caesarEncrypt(cipher, -shift);
}

export function vigenereEncrypt(plain, key) {
  if (!key) throw new Error("clé Vigenère vide");
  const shifts = [...key].map((c) => c.toLowerCase().codePointAt(0) - 97).filter((n) => n >= 0 && n < 26);
  if (!shifts.length) throw new Error("clé Vigenère : lettres a-z requises");
  let i = 0;
  return [...plain].map((ch) => {
    const c = ch.codePointAt(0);
    const s = shifts[i % shifts.length];
    if (c >= 65 && c <= 90) { i++; return String.fromCodePoint(((c - 65 + s) % 26) + 65); }
    if (c >= 97 && c <= 122) { i++; return String.fromCodePoint(((c - 97 + s) % 26) + 97); }
    return ch;
  }).join("");
}

export function vigenereDecrypt(cipher, key) {
  if (!key) throw new Error("clé Vigenère vide");
  const shifts = [...key].map((c) => c.toLowerCase().codePointAt(0) - 97).filter((n) => n >= 0 && n < 26);
  let i = 0;
  return [...cipher].map((ch) => {
    const c = ch.codePointAt(0);
    const s = shifts[i % shifts.length];
    if (c >= 65 && c <= 90) { i++; return String.fromCodePoint(((c - 65 - s + 26) % 26) + 65); }
    if (c >= 97 && c <= 122) { i++; return String.fromCodePoint(((c - 97 - s + 26) % 26) + 97); }
    return ch;
  }).join("");
}

export function xorCrypt(data, keyBytes) {
  if (!keyBytes.length) throw new Error("clé XOR vide");
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ keyBytes[i % keyBytes.length];
  return out;
}

/** RC4 (ARC4) — KSA + PRGA, écriture minimale pour la démo. */
export function rc4Crypt(data, keyBytes) {
  if (!keyBytes.length) throw new Error("clé RC4 vide");
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + keyBytes[i % keyBytes.length]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(data.length);
  let i = 0; j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
    out[k] = data[k] ^ S[(S[i] + S[j]) & 255];
  }
  return out;
}

/** Helpers texte ↔ hex pour César / Vigenère (stockage hex du texte transformé). */
export function textToHex(text) { return bytesToHex(utf8ToBytes(text)); }
export function hexToText(hex) { return bytesToUtf8(hexToBytes(hex)); }
