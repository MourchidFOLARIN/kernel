/** ChaCha20-Poly1305 via @noble/ciphers (vendor local). */
import { chacha20poly1305 } from "../../vendor/noble-ciphers.mjs";

export function chachaEncrypt(key32, nonce12, plain) {
  const c = chacha20poly1305(key32, nonce12);
  const sealed = c.encrypt(plain); // ciphertext || tag(16)
  return {
    ciphertext: sealed.slice(0, sealed.length - 16),
    tag: sealed.slice(sealed.length - 16),
  };
}

export function chachaDecrypt(key32, nonce12, cipher, tag) {
  const c = chacha20poly1305(key32, nonce12);
  const sealed = new Uint8Array(cipher.length + tag.length);
  sealed.set(cipher); sealed.set(tag, cipher.length);
  try {
    return c.decrypt(sealed);
  } catch (e) {
    const err = new Error("échec d'intégrité (ChaCha20-Poly1305)");
    err.integrity = false;
    throw err;
  }
}
