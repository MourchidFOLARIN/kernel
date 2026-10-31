/**
 * API unique de chiffrement / déchiffrement côté client.
 *
 * La clé (hex, 32 octets) est fournie par keys.js / getConversationKey selon le
 * mode de distribution : broadcast (serveur), password (PBKDF2), x25519 (ECDH).
 *
 * Format stocké / WS (inchangé) :
 *   { algo, mode, iv, ciphertext, tag }  — tout en hex sauf algo/mode.
 * Pour algo="Aucun" : ciphertext = UTF-8 du clair en hex, iv/tag vides.
 */
import { caesarDecrypt, caesarEncrypt, hexToText, rc4Crypt, textToHex,
         vigenereDecrypt, vigenereEncrypt, xorCrypt } from "./classical.js";
import { chachaDecrypt, chachaEncrypt } from "./chacha.js";
import { forgeDecrypt, forgeEncrypt } from "./forge-algos.js";
import { bytesToHex, bytesToUtf8, hexToBytes, keyBytesFromHex, randomBytes,
         truncateKeyDisplay, utf8ToBytes } from "./utils.js";

/** Specs : { family, mode, keyLen, ivLen, needsTag } */
export const ALGOS = {
  "Aucun":               { family: "none",   mode: "clair", keyLen: 0,  ivLen: 0,  needsTag: false },
  "César":               { family: "caesar", mode: "clair", keyLen: 1,  ivLen: 0,  needsTag: false },
  "Vigenère":            { family: "vigenere", mode: "clair", keyLen: 0, ivLen: 0, needsTag: false, keyIsText: true },
  "XOR":                 { family: "xor",    mode: "clair", keyLen: 4,  ivLen: 0,  needsTag: false },
  "RC4":                 { family: "rc4",    mode: "clair", keyLen: 16, ivLen: 0,  needsTag: false },
  "DES-ECB":             { family: "DES",    mode: "ECB",   keyLen: 8,  ivLen: 0,  needsTag: false },
  "DES-CBC":             { family: "DES",    mode: "CBC",   keyLen: 8,  ivLen: 8,  needsTag: false },
  "3DES-CBC":            { family: "3DES",   mode: "CBC",   keyLen: 24, ivLen: 8,  needsTag: false },
  "AES-ECB":             { family: "AES",    mode: "ECB",   keyLen: 16, ivLen: 0,  needsTag: false },
  "AES-CBC":             { family: "AES",    mode: "CBC",   keyLen: 16, ivLen: 16, needsTag: false },
  "AES-CTR":             { family: "AES",    mode: "CTR",   keyLen: 16, ivLen: 16, needsTag: false },
  "AES-GCM":             { family: "AES",    mode: "GCM",   keyLen: 16, ivLen: 12, needsTag: true },
  "ChaCha20-Poly1305":   { family: "chacha", mode: "AEAD",  keyLen: 32, ivLen: 12, needsTag: true },
};

export const ALGO_LIST = Object.keys(ALGOS);

/** Abstraction distribution de clé (étape 3 = broadcast uniquement). */
export function resolveKeyMaterial(settings, _conversationId) {
  const mode = settings?.key_distribution || "broadcast";
  if (mode === "broadcast") {
    return { kind: "broadcast", keyHex: settings.broadcast_key_hex || "" };
  }
  // password / x25519 : la clé est résolue par getConversationKey (app.js)
  return { kind: mode, keyHex: "" };
}

function vigenereKeyFromBroadcast(hex) {
  // Transforme les octets en lettres a-z pour Vigenère.
  const bytes = hexToBytes(hex);
  if (!bytes.length) return "kernel";
  return Array.from(bytes.slice(0, 8)).map((b) => String.fromCharCode(97 + (b % 26))).join("");
}

function caesarShiftFromKey(hex) {
  const b = hexToBytes(hex);
  return b.length ? (b[0] % 26) : 3;
}

/**
 * Chiffre un texte clair selon l'algo courant.
 * @returns {{ algo, mode, iv, ciphertext, tag, meta }}
 *   meta : infos pour le panneau Coulisses (jamais envoyées au serveur)
 */
export function encrypt(plainText, algoName, keyArg) {
  const spec = ALGOS[algoName];
  if (!spec) throw new Error(`algorithme inconnu : ${algoName}`);
  // `keyArg` : soit une clé hex (étape 4, via getConversationKey), soit l'objet settings (broadcast).
  const keyHex = typeof keyArg === "string" ? keyArg : resolveKeyMaterial(keyArg).keyHex;

  if (spec.family === "none") {
    return {
      algo: "Aucun", mode: "clair", iv: "", ciphertext: textToHex(plainText), tag: "",
      meta: { plain: plainText, keyDisplay: "—", integrity: true },
    };
  }

  if (spec.family === "caesar") {
    const shift = caesarShiftFromKey(keyHex);
    const out = caesarEncrypt(plainText, shift);
    return {
      algo: "César", mode: "clair", iv: "", ciphertext: textToHex(out), tag: "",
      meta: { plain: plainText, keyDisplay: `décalage ${shift}`, keyHex, integrity: true },
    };
  }

  if (spec.family === "vigenere") {
    const key = vigenereKeyFromBroadcast(keyHex);
    const out = vigenereEncrypt(plainText, key);
    return {
      algo: "Vigenère", mode: "clair", iv: "", ciphertext: textToHex(out), tag: "",
      meta: { plain: plainText, keyDisplay: key, keyHex, integrity: true },
    };
  }

  const plain = utf8ToBytes(plainText);

  if (spec.family === "xor") {
    const key = keyBytesFromHex(keyHex, spec.keyLen);
    const ct = xorCrypt(plain, key);
    return {
      algo: "XOR", mode: "clair", iv: "", ciphertext: bytesToHex(ct), tag: "",
      meta: { plain: plainText, keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true },
    };
  }

  if (spec.family === "rc4") {
    const key = keyBytesFromHex(keyHex, spec.keyLen);
    const ct = rc4Crypt(plain, key);
    return {
      algo: "RC4", mode: "clair", iv: "", ciphertext: bytesToHex(ct), tag: "",
      meta: { plain: plainText, keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true },
    };
  }

  if (spec.family === "chacha") {
    const key = keyBytesFromHex(keyHex, 32);
    const iv = randomBytes(12);
    const { ciphertext, tag } = chachaEncrypt(key, iv, plain);
    return {
      algo: "ChaCha20-Poly1305", mode: "AEAD", iv: bytesToHex(iv),
      ciphertext: bytesToHex(ciphertext), tag: bytesToHex(tag),
      meta: { plain: plainText, keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true },
    };
  }

  // DES / 3DES / AES via forge
  const key = keyBytesFromHex(keyHex, spec.keyLen);
  const iv = spec.ivLen ? randomBytes(spec.ivLen) : new Uint8Array(0);
  const { ciphertext, tag } = forgeEncrypt(spec.family, spec.mode, key, iv, plain);
  return {
    algo: algoName, mode: spec.mode, iv: bytesToHex(iv),
    ciphertext: bytesToHex(ciphertext), tag: tag ? bytesToHex(tag) : "",
    meta: { plain: plainText, keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true },
  };
}

/**
 * Déchiffre un message reçu. Retourne { plain, ok, error }.
 */
export function decrypt(msg, keyArg) {
  const algoName = msg.algo || "Aucun";
  const spec = ALGOS[algoName];
  // `keyArg` : soit une clé hex (étape 4, via getConversationKey), soit l'objet settings (broadcast).
  const keyHex = typeof keyArg === "string" ? keyArg : resolveKeyMaterial(keyArg).keyHex;

  try {
    if (!spec) throw new Error(`algo inconnu : ${algoName}`);

    if (spec.family === "none") {
      return { plain: hexToText(msg.ciphertext), ok: true, error: null,
        meta: { keyDisplay: "—", integrity: true } };
    }
    if (spec.family === "caesar") {
      const shift = caesarShiftFromKey(keyHex);
      const transformed = hexToText(msg.ciphertext);
      return { plain: caesarDecrypt(transformed, shift), ok: true, error: null,
        meta: { keyDisplay: `décalage ${shift}`, keyHex, integrity: true } };
    }
    if (spec.family === "vigenere") {
      const key = vigenereKeyFromBroadcast(keyHex);
      return { plain: vigenereDecrypt(hexToText(msg.ciphertext), key), ok: true, error: null,
        meta: { keyDisplay: key, keyHex, integrity: true } };
    }
    if (spec.family === "xor") {
      const key = keyBytesFromHex(keyHex, spec.keyLen);
      const pt = xorCrypt(hexToBytes(msg.ciphertext), key);
      return { plain: bytesToUtf8(pt), ok: true, error: null,
        meta: { keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true } };
    }
    if (spec.family === "rc4") {
      const key = keyBytesFromHex(keyHex, spec.keyLen);
      const pt = rc4Crypt(hexToBytes(msg.ciphertext), key);
      return { plain: bytesToUtf8(pt), ok: true, error: null,
        meta: { keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true } };
    }
    if (spec.family === "chacha") {
      const key = keyBytesFromHex(keyHex, 32);
      const pt = chachaDecrypt(key, hexToBytes(msg.iv), hexToBytes(msg.ciphertext), hexToBytes(msg.tag));
      return { plain: bytesToUtf8(pt), ok: true, error: null,
        meta: { keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true } };
    }
    // forge
    const key = keyBytesFromHex(keyHex, spec.keyLen);
    const pt = forgeDecrypt(spec.family, spec.mode, key, hexToBytes(msg.iv || ""),
                            hexToBytes(msg.ciphertext), hexToBytes(msg.tag || ""));
    return { plain: bytesToUtf8(pt), ok: true, error: null,
      meta: { keyDisplay: truncateKeyDisplay(bytesToHex(key)), keyHex: bytesToHex(key), integrity: true } };
  } catch (e) {
    return {
      plain: "", ok: false, error: e.message || String(e),
      meta: { keyDisplay: truncateKeyDisplay(keyHex), keyHex, integrity: e.integrity === false ? false : null },
    };
  }
}

export { truncateKeyDisplay, bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8 };
