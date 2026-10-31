/**
 * Tests Node : chiffrer puis déchiffrer redonne le clair pour CHAQUE algorithme.
 * Lance : node --test tests/js/crypto.test.mjs
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ALGO_LIST, decrypt, encrypt } from "../../static/js/crypto/index.js";

const SETTINGS = {
  key_distribution: "broadcast",
  // 32 octets — assez pour toutes les tailles de clé
  broadcast_key_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
};

const SAMPLES = [
  "Salut Kernel !",
  "The quick brown fox jumps over the lazy dog.",
  "Accents : été, naïve, ça — 你好 🔐",
  "A",
  "x".repeat(200),
];

describe("round-trip pour chaque algorithme", () => {
  for (const algo of ALGO_LIST) {
    it(algo, () => {
      for (const plain of SAMPLES) {
        const enc = encrypt(plain, algo, SETTINGS);
        assert.equal(enc.algo, algo === "Aucun" ? "Aucun" : enc.algo);
        const dec = decrypt(enc, SETTINGS);
        assert.equal(dec.ok, true, `${algo} : ${dec.error}`);
        assert.equal(dec.plain, plain, `${algo} mismatch`);
      }
    });
  }
});

describe("intégrité GCM / ChaCha", () => {
  it("AES-GCM détecte une modification", () => {
    const enc = encrypt("secret", "AES-GCM", SETTINGS);
    const tampered = { ...enc, ciphertext: flipHexBit(enc.ciphertext) };
    const dec = decrypt(tampered, SETTINGS);
    assert.equal(dec.ok, false);
    assert.match(dec.error, /intégrité|GCM/i);
  });
  it("ChaCha20-Poly1305 détecte une modification", () => {
    const enc = encrypt("secret", "ChaCha20-Poly1305", SETTINGS);
    const tampered = { ...enc, ciphertext: flipHexBit(enc.ciphertext) };
    const dec = decrypt(tampered, SETTINGS);
    assert.equal(dec.ok, false);
  });
  it("AES-CBC ne détecte PAS une modification (pas d'auth)", () => {
    const enc = encrypt("secret message!!", "AES-CBC", SETTINGS);
    const tampered = { ...enc, ciphertext: flipHexBit(enc.ciphertext) };
    const dec = decrypt(tampered, SETTINGS);
    // Soit ça « déchiffre » en garbage, soit bourrage échoue — pas d'auth tag.
    // On vérifie juste qu'on n'a PAS le message d'intégrité GCM.
    if (dec.ok) assert.notEqual(dec.plain, "secret message!!");
    else assert.doesNotMatch(dec.error || "", /intégrité \(GCM\)/);
  });
});

function flipHexBit(hex) {
  if (!hex || hex.length < 2) return "00";
  const b = parseInt(hex.slice(0, 2), 16) ^ 0xff;
  return b.toString(16).padStart(2, "0") + hex.slice(2);
}

import { derivePasswordKey, fingerprint, generateX25519, x25519SessionKey } from "../../static/js/crypto/keys.js";

describe("distribution des clés", () => {
  it("PBKDF2 : même mot de passe + même sel → même clé (Alice = Bob)", () => {
    const salt = "00112233445566778899aabbccddeeff";
    const a = derivePasswordKey("correct horse", salt, 1000);
    const b = derivePasswordKey("correct horse", salt, 1000);
    assert.equal(a, b);
    assert.equal(a.length, 64);
    assert.notEqual(derivePasswordKey("autre", salt, 1000), a);
    const enc = encrypt("via mot de passe", "AES-GCM", a);
    assert.equal(decrypt(enc, b).plain, "via mot de passe");
  });
  it("X25519 : secret de session identique pour A et B", () => {
    const A = generateX25519(), B = generateX25519();
    const kA = x25519SessionKey(A.privateKeyHex, B.publicKeyHex);
    const kB = x25519SessionKey(B.privateKeyHex, A.publicKeyHex);
    assert.equal(kA, kB);
    const enc = encrypt("via ECDH", "ChaCha20-Poly1305", kA);
    assert.equal(decrypt(enc, kB).plain, "via ECDH");
    // Nouvel appareil (nouvelle paire) → clé différente → échec
    const C = generateX25519();
    const kC = x25519SessionKey(C.privateKeyHex, A.publicKeyHex);
    assert.notEqual(fingerprint(kC), fingerprint(kA));
    assert.equal(decrypt(enc, kC).ok, false);
  });
});

import { avalanche, bruteForceCaesar, detectECB, nonceReuseXor } from "../../static/js/crypto/attacks.js";

describe("outils d'attaque", () => {
  it("brute force César retrouve le clair", () => {
    const settings = { broadcast_key_hex: "0a" + "00".repeat(31), key_distribution: "broadcast" };
    const enc = encrypt("bonjour le monde", "César", settings);
    const tries = bruteForceCaesar(enc.ciphertext);
    assert.equal(tries[0].plain.toLowerCase().includes("bonjour"), true);
  });
  it("détecte blocs ECB répétés", () => {
    const block = "00112233445566778899aabbccddeeff";
    const r = detectECB(block + block + "ffffffffffffffffffffffffffffffff", 16);
    assert.equal(r.suspicious, true);
    assert.equal(r.repeats >= 1, true);
  });
  it("XOR de deux chiffrés (nonce reuse)", () => {
    const x = nonceReuseXor("ff00", "0f0f");
    assert.equal(x[0], 0xf0);
    assert.equal(x[1], 0x0f);
  });
  it("avalanche compte les bits", () => {
    const r = avalanche("00", "ff");
    assert.equal(r.bits, 8);
  });
});

import { renderMarkdown } from "../../static/js/markdown.js";

describe("markdown", () => {
  it("échappe le HTML et rend le gras / code", () => {
    const html = renderMarkdown("**bonjour** <script>x</script> et `code`");
    assert.equal(html.includes("<script>"), false);
    assert.equal(html.includes("<strong>bonjour</strong>"), true);
    assert.equal(html.includes("md-inline"), true);
  });
  it("rend les blocs de code", () => {
    const html = renderMarkdown("```js\nconst a = 1;\n```");
    assert.equal(html.includes("md-code"), true);
    assert.equal(html.includes("tok-kw"), true);
  });
});
