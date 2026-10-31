/**
 * Algorithmes via node-forge (DES, 3DES, AES, modes ECB/CBC/CTR/GCM).
 * Ne réimplémente aucun de ces algorithmes.
 */
import forge from "../../vendor/forge.mjs";
import { pkcs7Pad, pkcs7Unpad } from "./utils.js";

function toBuf(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return s;
}
function fromBuf(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function forgeName(algo, mode) {
  if (algo === "DES") return mode === "ECB" ? "DES-ECB" : "DES-CBC";
  if (algo === "3DES") return "3DES-CBC";
  if (algo === "AES") {
    if (mode === "ECB") return "AES-ECB";
    if (mode === "CBC") return "AES-CBC";
    if (mode === "CTR") return "AES-CTR";
    if (mode === "GCM") return "AES-GCM";
  }
  throw new Error(`algo/mode forge inconnu : ${algo}-${mode}`);
}

function blockSize(algo) {
  return algo === "AES" ? 16 : 8;
}

export function forgeEncrypt(algo, mode, keyBytes, ivBytes, plainBytes) {
  const name = forgeName(algo, mode);
  if (mode === "GCM") {
    const cipher = forge.cipher.createCipher(name, toBuf(keyBytes));
    cipher.start({ iv: toBuf(ivBytes), tagLength: 128 });
    cipher.update(forge.util.createBuffer(toBuf(plainBytes)));
    cipher.finish();
    return { ciphertext: fromBuf(cipher.output.getBytes()), tag: fromBuf(cipher.mode.tag.getBytes()) };
  }
  const padded = mode === "CTR" ? plainBytes : pkcs7Pad(plainBytes, blockSize(algo));
  const cipher = forge.cipher.createCipher(name, toBuf(keyBytes));
  cipher.start(mode === "ECB" ? {} : { iv: toBuf(ivBytes) });
  cipher.update(forge.util.createBuffer(toBuf(padded)));
  if (!cipher.finish()) throw new Error("échec chiffrement forge");
  return { ciphertext: fromBuf(cipher.output.getBytes()), tag: null };
}

export function forgeDecrypt(algo, mode, keyBytes, ivBytes, cipherBytes, tagBytes) {
  const name = forgeName(algo, mode);
  if (mode === "GCM") {
    const decipher = forge.cipher.createDecipher(name, toBuf(keyBytes));
    decipher.start({ iv: toBuf(ivBytes), tagLength: 128, tag: toBuf(tagBytes) });
    decipher.update(forge.util.createBuffer(toBuf(cipherBytes)));
    if (!decipher.finish()) {
      const err = new Error("échec d'intégrité (GCM)");
      err.integrity = false;
      throw err;
    }
    return fromBuf(decipher.output.getBytes());
  }
  const decipher = forge.cipher.createDecipher(name, toBuf(keyBytes));
  decipher.start(mode === "ECB" ? {} : { iv: toBuf(ivBytes) });
  decipher.update(forge.util.createBuffer(toBuf(cipherBytes)));
  if (!decipher.finish()) throw new Error("échec déchiffrement forge");
  const raw = fromBuf(decipher.output.getBytes());
  return mode === "CTR" ? raw : pkcs7Unpad(raw, blockSize(algo));
}
