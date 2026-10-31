# Kernel

> **Là où ceux qui construisent se retrouvent.**

Plateforme de discussion pour une communauté tech (développement, cybersécurité, data, IA, DevOps, étudiants).

En coulisses, Kernel sert aussi de support à une **présentation technique** sur le chiffrement symétrique : l’administrateur choisit l’algorithme en direct, et un compte « attaquant » (Ève) peut observer ou retenir le trafic local. **Usage prévu : votre propre réseau (hotspot), avec des participants informés.** Ce n’est pas un produit de messagerie « ultra-sécurisé ».

Code, commentaires, README et interface en **français**.

---

## Éthique et cadre d’usage

- Exécutez Kernel **uniquement** sur un réseau que vous contrôlez (hotspot de téléphone, LAN de labo).
- Informez clairement les participants qu’il s’agit d’une démo (interception possible si `DEMO_MODE=true`).
- N’utilisez pas Kernel pour cibler des systèmes tiers ni pour contourner des mesures de sécurité sans autorisation.

---

## Installation

Prérequis : **Python 3.11+** (testé avec 3.13), `pip`. Node.js 20+ uniquement pour les tests JS crypto.

```bash
cd kernel
python3 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Le serveur écoute sur **http://0.0.0.0:3000**.
Sur la machine : http://127.0.0.1:3000

Au démarrage : création de `kernel.db` (SQLite) et des comptes / salons de démonstration.

### Variables d’environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `DEMO_MODE` | `true` | Active `/eve`, Coulisses, clé diffusée, force brute DES courte |
| `SECRET_KEY` | fichier `.secret_key` | Signature des cookies de session |
| `KERNEL_DB` | `./kernel.db` | Chemin SQLite |
| `KERNEL_HOST` / `KERNEL_PORT` | `0.0.0.0` / `3000` | Bind du serveur |

---

## Comptes de démonstration

| Pseudo | Mot de passe | Rôle |
|---|---|---|
| `alice` | `Alice123!` | membre |
| `bob` | `Bob123!` | membre |
| `admin` | `Admin123!` | admin (`/admin`) |
| `eve` | `Eve123!` | attaquant (`/eve`, si `DEMO_MODE=true`) |

---

## Trouver l’IP du serveur (hotspot)

Connectez les téléphones / PC au **même hotspot** que la machine qui lance Kernel.

**Linux**
```bash
ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.'
# ou
hostname -I
```

**macOS**
```bash
ipconfig getifaddr en0    # Wi-Fi souvent en0
# sinon : Préférences Système → Réseau → Wi-Fi → Détails
```

**Windows (Invite de commandes)**
```bat
ipconfig
```
Repérez l’adresse IPv4 de l’adaptateur Wi-Fi / « Accès réseau local sans fil » (souvent `192.168.43.x` ou `192.168.137.x` derrière un hotspot téléphone).

Les participants ouvrent : `http://<IP>:3000`

### Ouvrir le port 3000

**Linux (ufw)**
```bash
sudo ufw allow 3000/tcp
sudo ufw reload
```

**Windows** : Pare-feu Windows → Règles de trafic entrant → Nouvelle règle → Port TCP 3000 → Autoriser.

**macOS** : en général pas de pare-feu bloquant en LAN ; si « Pare-feu » est actif, autorisez Python / Terminal.

### Dépannage hotspot

| Symptôme | Piste |
|---|---|
| Les autres ne joignent pas le serveur | Vérifier l’**IP** (pas 127.0.0.1), le **port 3000**, et que Kernel tourne sur `0.0.0.0` |
| Connexion OK puis coupures | Isolation client (AP isolation) du hotspot : certains téléphones empêchent le trafic entre clients — désactiver si possible, ou utiliser un autre point d’accès |
| Page blanche / assets manquants | Rester en HTTP (pas HTTPS) ; `crypto.subtle` n’est pas requis (libs locales dans `/static/vendor`) |
| Cookie / login perdu | Même hôte (IP) pour tous ; pas de bascule IP pendant la session |

---

## Rôle de `DEMO_MODE`

| | `DEMO_MODE=true` (défaut) | `DEMO_MODE=false` |
|---|---|---|
| `/eve` | Accessible au rôle attaquant | **404** |
| Panneau **Coulisses** (admin/attaquant) | Visible sous les messages | Absent |
| Clé diffusée en clair (`broadcast`) | Autorisée | Désactivée côté clients (bascule forcée hors broadcast ; `broadcast_key_hex` non envoyé) |
| Bouton « Clé DES 24 bits » | Disponible | Indisponible |
| Interception WS Ève | Active si cochée | Inactive |

Lancer hors démo :
```bash
DEMO_MODE=false python run.py
```

---

## Interception réseau (démo)

### Wireshark

1. Démarrer Kernel, connecter les clients au hotspot.
2. Wireshark → interface Wi-Fi / hotspot.
3. Filtre : `tcp.port == 3000`
4. Suivre le flux HTTP / WebSocket : on voit les trames JSON (`ciphertext` en hex, et la clé si mode `broadcast`).

### Burp Suite

1. Proxy → Options → Add listener **`0.0.0.0:8080`**.
2. Rediriger (invisible proxy ou règle) vers le serveur Kernel `IP:3000`.
3. Les clients pointent vers Burp (proxy HTTP) ou utilisent un listener en mode redirect.
4. Kernel utilise **`ws://` simple**, sans dépendance stricte aux en-têtes Host/Origin — compatible avec un proxy man-in-the-middle local.

---

## Algorithmes (chiffrement dans le navigateur)

| Algorithme | Bibliothèque | Notes |
|---|---|---|
| Aucun | — | Clair hexadécimal (UTF-8) |
| César, Vigenère, XOR, RC4 | Code maison | Pédagogiques |
| DES-ECB, DES-CBC, 3DES-CBC | node-forge | |
| AES-ECB, AES-CBC, AES-CTR, AES-GCM | node-forge | GCM = authentifié |
| ChaCha20-Poly1305 | @noble/ciphers | Authentifié |

Le serveur ne stocke **jamais** le clair (sauf algo `Aucun`, hex du texte). Colonnes : `algo`, `mode`, `iv`, `ciphertext`, `tag`, horodatage, `key_dist`, `key_fp`.

Vendor local (aucun CDN) : `static/vendor/forge.mjs`, `noble-ciphers.mjs`, `noble-curves.mjs` (rebuild : `node tools/vendor-build/build.mjs`).

---

## Distribution des clés (3 modes)

| Mode | Fonctionnement | Limite |
|---|---|---|
| **broadcast** | Le serveur diffuse `broadcast_key_hex` (faille volontaire : Ève la voit) | Toute personne qui voit le trafic/API obtient la clé |
| **password** | Mot de passe commun → PBKDF2 (50k, SHA-256) côté navigateur ; le serveur ne relaie que le **sel** | Changer d’appareil / oublier le code → historique illisible |
| **x25519** | ECDH ; privée en IndexedDB ; publique relayée ; session = SHA-256(secret). Groupes : clé de salon emballée pour chaque membre | Nouvel appareil / IndexedDB vidé → messages passés illisibles |

Chaque message porte `key_dist` + empreinte `key_fp` (8 hex de SHA-256 de la clé) pour retrouver la bonne clé en cache local.

---

## Mode présentation (admin)

> [!TIP]
> Pour un conducteur complet étape par étape, la préparation réseau, les attaques et le minutage d'une session, consultez le guide dédié : **[Guide de démonstration de A à Z](docs/DEMONSTRATION.md)**.

Dans `/admin` → **Étape suivante** :

1. Clair (Aucun)  
2. César  
3. AES-ECB (motifs visibles)  
4. AES-CBC (modification non détectée)  
5. AES-GCM (modification détectée)  
6. ECDH X25519 + AES-GCM  

Déroulé suggéré : Alice et Bob discutent ; admin avance les étapes ; Ève montre le flux / l’interception / les outils (ECB, avalanche, DES 24 bits).

---

## Discuter

1. **Créer son compte** : chaque personne ouvre `http://<IP-du-serveur>:3000/rejoindre` depuis **son** appareil. Elle est connectée automatiquement et arrive sur `/app`, déjà membre de **#général** et **#entraide**.
2. **Écrire à quelqu’un** : gros bouton **✎ Nouveau message** (barre de gauche ou accueil). Une fenêtre liste **tous les membres inscrits** (sauf vous) : initiales, nom, @pseudo, domaine, point vert si en ligne. Tapez quelques lettres du pseudo ou du nom pour filtrer (accents ignorés, flèches ↑↓ + Entrée au clavier), puis cliquez sur la personne : la conversation s’ouvre, **le curseur est déjà dans la zone de saisie**.
   - Même chose depuis l’onglet **Membres** (recherche + clic sur un membre) ou depuis les pastilles « en ligne » de l’accueil.
3. **Envoyer** : **Entrée** ou le bouton **Envoyer** ; **Maj+Entrée** = retour à la ligne. Le message s’affiche aussitôt chez vous (🕓 puis ✓ / ✓✓ / ✓✓ vert = lu) et en temps réel chez le destinataire (badge de non-lus).
4. **En cas d’échec** (membre qui vous a bloqué, coupure réseau…) : un message d’erreur clair s’affiche en bas de l’écran et la bulle indique « ⚠ Non envoyé — réessayer » (cliquez pour renvoyer).
5. **Salons** : onglet **Salons** (rejoindre / ouvrir / quitter). **Groupes** : « ＋ Nouveau groupe » dans l’onglet Discussions. **Demandes** : demandes de contact reçues / envoyées / contacts.
6. **Sur une bulle** : survol (ordinateur) ou toucher (mobile) → réagir, répondre, modifier, supprimer, signaler.
7. **Connexion perdue** : un bandeau s’affiche et la reconnexion est automatique ; l’historique est rechargé.

Chaque action affiche une confirmation (toast) ou une erreur lisible ; il n’y a plus aucune boîte `alert()/prompt()` native.

Captures : `docs/screens/` (bureau et mobile 375 px).

### Si « les boutons ne font rien » après une mise à jour

Les fichiers JS/CSS sont servis sous un chemin versionné (`/static/v-<empreinte>/…`, l’empreinte change à chaque modification) avec `Cache-Control: no-cache`, et les pages HTML en `no-store` : le navigateur ne peut plus mélanger d’anciens et de nouveaux modules. **Redémarrez le serveur après avoir copié une nouvelle version.** Si le script de l’application ne démarre pas, un bandeau « Rechargez la page (Ctrl+Maj+R) » apparaît au bout de 8 s.

## Tests

```bash
source .venv/bin/activate
pytest -q
node --test tests/js/
```

- **Python** : auth, droits admin/Ève, messages, clés, salons, contacts, groupes, signalements, annuaire `/api/users/all`, en-têtes de cache, audit textes publics, `DEMO_MODE=false`.
- **JS** : round-trip **chaque** algorithme, intégrité GCM/ChaCha, PBKDF2, X25519, outils d’attaque, Markdown.

Tests navigateur (puppeteer-core ; Chrome par défaut, Firefox avec `AUDIT_BROWSER=firefox FIREFOX=/chemin/firefox`) :

```bash
npm i puppeteer-core                                   # une fois
BASE=http://<IP>:3000 node tools/e2e-multiuser.mjs     # usage réel à 3 comptes
BASE=http://<IP>:3000 node tools/audit-buttons.mjs     # clique TOUT, échoue si un clic ne fait rien
```

- `e2e-multiuser.mjs` : 3 comptes via `/rejoindre` (dont un mobile 375 px) ; « Nouveau message » → recherche par pseudo → clic → curseur dans la saisie → Entrée ; réception en temps réel + réponse via « Envoyer » ; Maj+Entrée ; onglet Membres sur mobile ; #général à 3 ; rechargement complet ; erreur visible après blocage ; coupure/reconnexion WebSocket ; zéro erreur console.
- `audit-buttons.mjs` : pour chaque état (accueil, conversation, chaque onglet, chaque fenêtre) en 1280 px et 375 px, recharge la page puis fait un vrai clic souris sur chaque bouton/lien/onglet visible ; échoue si l’élément est recouvert, si le clic ne produit aucun effet visible, ou s’il provoque une erreur console/réseau ou une boîte native.
- `tools/e2e-keys.mjs` : smoke des modes de clés.

---

## Arborescence

```
kernel/
├── app/                 # FastAPI : modèles, sécurité, routes, WS, templates
├── static/
│   ├── css/ js/         # UI + crypto client + Eve/admin
│   └── vendor/          # forge, noble-ciphers, noble-curves (ESM locaux)
├── content/             # Textes publics FR (sans vocabulaire crypto)
├── docs/                # Guide de démo pas à pas (DEMONSTRATION.md) et captures
├── tests/               # pytest + tests/js
├── tools/               # Scripts d'audit E2E et build des vendors
├── crypto_atelier.py    # Script pédagogique autonome (de César à X25519 en Python)
├── run.py
├── requirements.txt
└── README.md
```

---

## Limites connues

- Un seul processus uvicorn (hub WS / interception Ève en mémoire).
- Pas de HTTPS (volontaire pour la démo LAN / Burp).
- Priorité 3 non livrée : messages éphémères, épinglage, export.
- Les nouveaux membres d’un salon reçoivent la clé de groupe x25519 au prochain message d’un membre déjà équipé (ou en générant la leur).
- Le bouton « Quitter » d’un salon est respecté au redémarrage (seuls les comptes sans aucun salon sont réinscrits à #général/#entraide).
- Coloration syntaxique Markdown basique.
- Fichiers ≤ ~700 Ko.
- X25519 / password : perte d’historique sur nouvel appareil.
- Notifications : titre d’onglet + bip minimal (pas de push).

---

## Licence

Projet éducatif / communautaire en version bêta.
