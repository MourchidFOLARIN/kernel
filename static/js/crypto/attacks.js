/**
 * Outils d'attaque pédagogiques (modules purs, testables sous Node).
 * Ne servent qu'à la démonstration sur réseau local avec participants informés.
 */
import { caesarDecrypt, textToHex } from "./classical.js";
import { bytesToUtf8, hexToBytes } from "./utils.js";
import { hexToText } from "./classical.js";

const FR_FREQ = "esaitnrulodcpmvqfbghjxyzwk";

/** Score d'un texte français approximatif (plus haut = plus plausible). */
export function frenchScore(text) {
  let score = 0;
  const lower = text.toLowerCase();
  for (const ch of lower) {
    const idx = FR_FREQ.indexOf(ch);
    if (idx >= 0) score += (26 - idx);
    else if (ch === " ") score += 10;
  }
  return score / Math.max(1, text.length);
}

/** Force brute César : 26 décalages, triés par plausibilité. cipherHex = hex du texte transformé. */
export function bruteForceCaesar(cipherHex) {
  const cipher = hexToText(cipherHex);
  const tries = [];
  for (let s = 0; s < 26; s++) {
    const plain = caesarDecrypt(cipher, s);
    tries.push({ shift: s, plain, score: frenchScore(plain) });
  }
  tries.sort((a, b) => b.score - a.score);
  return tries;
}

/** Analyse fréquentielle d'un texte (compte des lettres a-z). */
export function frequencyAnalysis(text) {
  const counts = {};
  for (const ch of text.toLowerCase()) {
    if (ch >= "a" && ch <= "z") counts[ch] = (counts[ch] || 0) + 1;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

/**
 * Vigenère : estime la longueur de clé (indice de coïncidence) puis
 * casse chaque colonne comme un César. cipherHex = hex du texte transformé.
 */
export function bruteForceVigenere(cipherHex, maxLen = 8) {
  const letters = hexToText(cipherHex).toLowerCase().replace(/[^a-z]/g, "");
  if (!letters) return { keyLength: 0, key: "", plain: "" };
  let best = { ic: 0, len: 1 };
  for (let len = 1; len <= maxLen; len++) {
    let total = 0;
    for (let i = 0; i < len; i++) {
      const col = [...letters].filter((_, j) => j % len === i).join("");
      total += indexOfCoincidence(col);
    }
    const ic = total / len;
    if (ic > best.ic) best = { ic, len };
  }
  const len = best.len;
  let key = "";
  for (let i = 0; i < len; i++) {
    const col = [...letters].filter((_, j) => j % len === i).join("");
    const guess = bruteForceCaesar(textToHex(col))[0];
    key += String.fromCharCode(97 + guess.shift);  // décalage de colonne = lettre de clé
  }
  return { keyLength: len, key, ic: best.ic };
}

function indexOfCoincidence(text) {
  const n = text.length;
  if (n < 2) return 0;
  const counts = {};
  for (const c of text) counts[c] = (counts[c] || 0) + 1;
  let sum = 0;
  for (const c in counts) sum += counts[c] * (counts[c] - 1);
  return sum / (n * (n - 1));
}

/** Détection ECB : repère les blocs de `blockBytes` identiques. */
export function detectECB(cipherHex, blockBytes = 16) {
  const step = blockBytes * 2;
  const blocks = [];
  for (let i = 0; i < cipherHex.length; i += step) blocks.push(cipherHex.slice(i, i + step));
  const seen = new Map();
  let repeats = 0;
  blocks.forEach((b, i) => {
    if (seen.has(b)) { repeats++; seen.get(b).push(i); }
    else seen.set(b, [i]);
  });
  const duplicates = [...seen.entries()].filter(([, idx]) => idx.length > 1);
  return { blocks, duplicates, repeats, suspicious: repeats > 0 };
}

/** Réutilisation de nonce : XOR de deux chiffrés (CTR/ChaCha) → XOR des deux clairs. */
export function nonceReuseXor(hexA, hexB) {
  const a = hexToBytes(hexA), b = hexToBytes(hexB);
  const n = Math.min(a.length, b.length);
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** Effet d'avalanche : nombre de bits qui diffèrent entre deux chiffrés hex. */
export function avalanche(hexA, hexB) {
  const a = hexToBytes(hexA), b = hexToBytes(hexB);
  const n = Math.min(a.length, b.length);
  let bits = 0;
  for (let i = 0; i < n; i++) {
    let x = a[i] ^ b[i];
    while (x) { bits += x & 1; x >>= 1; }
  }
  const totalBits = n * 8;
  return { bits, totalBits, ratio: totalBits ? bits / totalBits : 0 };
}
