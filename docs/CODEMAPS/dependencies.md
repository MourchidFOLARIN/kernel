<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~700 -->
# Cartographie des Dépendances : Kernel

Kernel minimise strictement ses dépendances externes pour garantir un fonctionnement 100 % autonome hors-ligne ou sur réseau local sans accès à Internet.

---

## 1. Dépendances Backend Python (`requirements.txt`)

| Paquet | Version minimale | Rôle dans Kernel |
|---|---|---|
| **`fastapi`** | `>=0.110` | Framework web ASGI pour les routes REST et le point d'entrée WebSocket. |
| **`uvicorn[standard]`**| `>=0.29` | Serveur web asynchrone haute performance hébergeant FastAPI. |
| **`SQLAlchemy`** | `>=2.0` | ORM moderne et gestion des modèles de données SQLite. |
| **`argon2-cffi`** | `>=23.1` | Hachage résistant aux attaques GPU/ASIC pour les mots de passe (Argon2id). |
| **`itsdangerous`** | `>=2.1` | Signature cryptographique et vérification d'intégrité des cookies de session. |
| **`Jinja2`** | `>=3.1` | Moteur de gabarits pour le rendu côté serveur (SSR) avec échappement automatique anti-XSS. |
| **`python-multipart`** | `>=0.0.9`| Traitement des formulaires web et des envois de fichiers (avatars). |
| **`pydantic[email]`** | `>=2.6` | Validation de données et sérialisation des requêtes/réponses d'API. |
| **`email-validator`** | `>=2.1` | Validation rigoureuse de la syntaxe des adresses électroniques. |
| **`markupsafe`** | `>=2.1` | Échappement sécurisé des chaînes HTML. |
| **`cryptography`** | `>=46.0` | Utilisé par le script pédagogique `crypto_atelier.py` pour émuler et tester tous les algorithmes. |
| **`httpx`** | `>=0.27` | Client HTTP asynchrone pour les tests d'intégration avec `TestClient`. |
| **`pytest`** | `>=8.0` | Framework d'exécution des 54 tests unitaires et fonctionnels backend. |

---

## 2. Bibliothèques Cryptographiques Client (`static/vendor/`)

Aucun script n'est téléchargé depuis un CDN public. Tous les modules tiers JavaScript sont construits sous forme d'ES Modules locaux autonomes via **esbuild** dans [`tools/vendor-build/build.mjs`](file:///home/admin/Project/kernel/tools/vendor-build/build.mjs) :

| Fichier Vendor | Bibliothèque Source | Rôle dans le Navigateur |
|---|---|---|
| [`static/vendor/forge.mjs`](file:///home/admin/Project/kernel/static/vendor/forge.mjs) | `node-forge` (v1.4) | Fournit les chiffrements par blocs : DES-ECB, DES-CBC, 3DES-CBC, AES-ECB, AES-CBC, AES-CTR et AES-GCM. |
| [`static/vendor/noble-ciphers.mjs`](file:///home/admin/Project/kernel/static/vendor/noble-ciphers.mjs) | `@noble/ciphers` (v2.4) | Fournit l'algorithme AEAD moderne de flux ChaCha20-Poly1305 (RFC 8439). |
| [`static/vendor/noble-curves.mjs`](file:///home/admin/Project/kernel/static/vendor/noble-curves.mjs) | `@noble/curves` (v2.4) | Fournit la cryptographie sur courbe elliptique Curve25519 (échange Diffie-Hellman X25519). |

*Rebuild one-shot en cas de mise à jour :*
```bash
cd tools/vendor-build && npm install && node build.mjs
```

---

## 3. Outils de Test et d'Audit (`package.json` & `tools/`)

| Outil | Type | Usage |
|---|---|---|
| **`node:test`** | Node.js standard | Exécute les 24 tests unitaires cryptographiques (`npm run test:crypto`). |
| **`puppeteer-core`** | `devDependencies` | Pilote un navigateur Chromium sans tête pour les audits complets d'interface et d'usage multi-utilisateurs. |
| [`tools/e2e-multiuser.mjs`](file:///home/admin/Project/kernel/tools/e2e-multiuser.mjs) | Script E2E | Simule 3 utilisateurs réels simultanés sur mobile et desktop avec messagerie temps réel. |
| [`tools/audit-buttons.mjs`](file:///home/admin/Project/kernel/tools/audit-buttons.mjs) | Script d'audit | Clique automatiquement chaque bouton et onglet du projet en 1280 px et 375 px pour traquer les clics sans effet. |
| [`tools/e2e-keys.mjs`](file:///home/admin/Project/kernel/tools/e2e-keys.mjs) | Script E2E | Vérifie les trois modes de distribution des clés (broadcast, password, x25519). |
