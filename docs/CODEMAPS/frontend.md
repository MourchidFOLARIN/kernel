<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~800 -->
# Cartographie Frontend & Crypto Client : Kernel

Le frontend de Kernel repose sur du **Vanilla JavaScript (ES Modules natifs)** et du **CSS sans framework**, sans dépendance à des CDN externes (100 % autonome pour un réseau local).

---

## 1. Arborescence des Gabarits HTML (`app/templates/`)

```
base.html (Gabarit racine : en-têtes SEO, balises CSRF, thème, toasts, modal)
  ├── home.html               # Page d'accueil publique (statistiques réelles, slogans)
  ├── landing.html            # Pages d'atterrissage thématiques (/dev, /cybersecurite, /data-ia)
  ├── features.html           # Présentation des fonctionnalités communautaires
  ├── communities.html        # Annuaire des salons avec filtres par domaine
  ├── events.html             # Liste des ateliers, rencontres et défis tech
  ├── about.html              # Équipe et histoire du projet
  ├── faq.html                # Foire aux questions
  ├── contact.html            # Formulaire de contact public
  ├── prose.html              # Pages textuelles Markdown (règles, légal, confidentialité)
  ├── join.html & login.html  # Inscription et connexion avec pré-sélection de domaine
  ├── forgot.html             # Demande et saisie de code de réinitialisation
  ├── app.html                # SPA de messagerie (barre latérale, conversation, tiroirs)
  ├── admin.html              # Tableau de bord d'administration et pilotage de la démo
  ├── eve.html                # Interface de l'attaquant (flux brut, interception, attaques)
  └── error.html              # Pages d'erreurs conviviales (401, 403, 404, 500)
```

---

## 2. Modules JavaScript Applicatifs (`static/js/`)

| Fichier | Dépendances | Fonction principale |
|---|---|---|
| [`static/js/app.js`](file:///home/admin/Project/kernel/static/js/app.js) | `api.js`, `crypto/index.js`, `markdown.js` | SPA de messagerie : connexion WebSocket, rechargement d'historique, rendu des bulles déchiffrées, panneau « Coulisses », gestion des pièces jointes, accusés et frappe. |
| [`static/js/api.js`](file:///home/admin/Project/kernel/static/js/api.js) | — | Client HTTP léger injectant systématiquement le jeton CSRF (`X-CSRF-Token`). |
| [`static/js/eve.js`](file:///home/admin/Project/kernel/static/js/eve.js) | `api.js`, `crypto/attacks.js`, `crypto/des-brute.js` | Tableau de bord Ève : flux de trames WebSocket en direct, mise en attente (held), modification de paquets MiTM et exécution des attaques. |
| [`static/js/admin.js`](file:///home/admin/Project/kernel/static/js/admin.js) | `api.js` | Contrôle interactif du mode présentation (boutons étape suivante / reset, changement d'algorithme, clé DES 24 bits). |
| [`static/js/forms.js`](file:///home/admin/Project/kernel/static/js/forms.js) | `api.js` | Validation côté client et soumission AJAX des formulaires d'authentification et de profil. |
| [`static/js/markdown.js`](file:///home/admin/Project/kernel/static/js/markdown.js) | — | Mini-parser Markdown sécurisé (échappement anti-XSS, gras, italique, blocs de code mono). |
| [`static/js/theme.js`](file:///home/admin/Project/kernel/static/js/theme.js) | — | Gestionnaire du thème clair / sombre stocké en `localStorage`. |

---

## 3. Sous-système Cryptographique (`static/js/crypto/`)

Tout le chiffrement et le déchiffrement s'effectue dans le navigateur avant envoi réseau.

```
                      [ index.js ]  (Façade principale)
                       ├── encrypt(plaintext, algo, settings)
                       └── decrypt(message, settings)
                                 │
         ┌───────────────────────┼────────────────────────┐
         ▼                       ▼                        ▼
  [ classical.js ]       [ forge-algos.js ]         [ chacha.js ]
  - Aucun (hex UTF-8)    - DES-ECB, DES-CBC        - ChaCha20-Poly1305
  - César, Vigenère      - 3DES-CBC                  (via noble-ciphers)
  - XOR, RC4             - AES-ECB, CBC, CTR, GCM
                           (via forge.mjs)
                                 │
         ┌───────────────────────┴────────────────────────┐
         ▼                                                ▼
   [ keys.js ]                                    [ keymanager.js ]
  - PBKDF2 (dérivation mot de passe)              - Cache de clés local (IndexedDB)
  - X25519 ECDH (génération & secret)             - Empreintes SHA-256 (key_fp)
  - noble-curves.mjs                              - Wrapping de clés de salon (AES-GCM)
```

---

## 4. Outils d'Attaque & Cryptanalyse (`attacks.js` & `des-brute.js`)

- **`bruteForceCaesar(ciphertext)`** : teste les 25 décalages et trie selon la fréquence des lettres françaises.
- **`detectECB(ciphertextHex)`** : découpe le chiffré en blocs de 16 octets et détecte les répétitions trahissant la structure des données.
- **`nonceReuseXor(ctA, ctB)`** : calcule $C_1 \oplus C_2 = P_1 \oplus P_2$ pour annuler le flux de clé lors de la réutilisation de nonce.
- **`avalanche(plainA, plainB, algo)`** : compte le ratio de bits inversés entre deux chiffrés dont le clair diffère d'un seul caractère (~50 % attendu).
- **`bruteForceDES24()`** : worker asynchrone qui parcourt l'espace de clé 24 bits (3 octets variables) pour retrouver la clé en quelques secondes en démo.

---

## 5. Ergonomie et Règles d'Interface (UX)

- **Zéro boîte native** : aucune utilisation de `alert()` ou `prompt()`. Remplacement par des toasts animés (`showToast()`) et des modals accessibles.
- **Gestion des pannes réseau** : bandeau d'alerte automatique lors des coupures WebSocket avec reconnexion exponentielle (jusqu'à 8 s).
- **Indicateurs de statut** : `🕓` (envoi), `✓` (reçu par le serveur), `✓✓` (remis au destinataire), `✓✓ vert` (lu).

