/**
 * Dérivation / échange de clés — fonctions pures (navigateur + Node).
 *
 * - password : PBKDF2-HMAC-SHA256 (node-forge), 50 000 itérations, sel public par conversation.
 * - x25519   : ECDH (@noble/curves), clé de session = SHA-256(secret partagé).
 * - fingerprint : 4 premiers octets de SHA-256(clé) — publiée avec chaque message
 *   pour savoir si on détient la bonne clé (ne révèle pas la clé).
 */
import forge from "../../vendor/forge.mjs";
import { x25519 } from "../../vendor/noble-curves.mjs";
import { bytesToHex, hexToBytes, randomBytes } from "./utils.js";

export const PBKDF2_ITERATIONS = 50000;

function bin(u8) { let s = ""; for (const b of u8) s += String.fromCharCode(b); return s; }

export function sha256Hex(bytes) {
  const md = forge.md.sha256.create();
  md.update(bin(bytes));
  return md.digest().toHex();
}

export function derivePasswordKey(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const pwd = forge.util.encodeUtf8(password);
  const key = forge.pkcs5.pbkdf2(pwd, bin(hexToBytes(saltHex)), iterations, 32, forge.md.sha256.create());
  return forge.util.bytesToHex(key);
}

export function generateX25519() {
  const priv = randomBytes(32);
  return { privateKeyHex: bytesToHex(priv), publicKeyHex: bytesToHex(x25519.getPublicKey(priv)) };
}

export function x25519SessionKey(myPrivHex, peerPubHex) {
  const shared = x25519.getSharedSecret(hexToBytes(myPrivHex), hexToBytes(peerPubHex));
  return sha256Hex(shared);
}

export function fingerprint(keyHex) {
  return keyHex ? sha256Hex(hexToBytes(keyHex)).slice(0, 8) : "";
}
