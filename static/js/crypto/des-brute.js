/**
 * Force brute DES avec clé volontairement RÉDUITE à 24 bits : seuls les 3 derniers
 * octets de la clé varient (les 5 premiers sont connus/fixés à 0). Démonstration de
 * l'insuffisance d'un espace de clés trop petit. ~16,7 M essais au pire.
 */
import { forgeDecrypt } from "./forge-algos.js";
import { bytesToHex, bytesToUtf8, hexToBytes } from "./utils.js";

export function isPrintable(bytes) {
  let printable = 0;
  for (const b of bytes) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 160) printable++;
  return printable / Math.max(1, bytes.length) > 0.9;
}

/**
 * @param onProgress (tried, keyHex) appelée périodiquement
 * @returns { found, keyHex, plain, tried } | yield via callback
 */
export function bruteForceDES24({ mode, ivHex, cipherHex, tagHex = "", known = "0000000000",
                                  onProgress, chunk = 20000, maxTried = 1 << 24 }) {
  const iv = hexToBytes(ivHex || "");
  const cipher = hexToBytes(cipherHex);
  const tag = hexToBytes(tagHex || "");
  const prefix = hexToBytes(known); // 5 octets connus
  let tried = 0;
  return {
    step() {
      const end = Math.min(tried + chunk, maxTried);
      for (; tried < end; tried++) {
        const key = new Uint8Array(8);
        key.set(prefix);
        key[5] = (tried >> 16) & 0xff;
        key[6] = (tried >> 8) & 0xff;
        key[7] = tried & 0xff;
        try {
          const pt = forgeDecrypt("DES", mode, key, iv, cipher, tag);
          if (isPrintable(pt)) {
            return { done: true, found: true, keyHex: bytesToHex(key),
                     plain: bytesToUtf8(pt), tried };
          }
        } catch { /* mauvaise clé */ }
      }
      if (onProgress) onProgress(tried, (tried).toString(16));
      return { done: tried >= maxTried, found: false, tried };
    },
    get tried() { return tried; },
  };
}
