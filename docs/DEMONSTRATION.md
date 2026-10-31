# Guide de Démonstration de A à Z : Kernel

Ce document détaille le déroulé complet d'un atelier ou d'une présentation technique interactive avec **Kernel**. Il est conçu pour être suivi pas à pas par le présentateur et l'équipe d'animation (ou en autonomie pour s'entraîner).

---

## Sommaire

1. [Objectifs et concept pédagogique](#1-objectifs-et-concept-pédagogique)
2. [Architecture de la démo & Rôles](#2-architecture-de-la-démo--rôles)
3. [Préparation technique (J - 30 minutes)](#3-préparation-technique-j---30-minutes)
4. [Mise en place des écrans](#4-mise-en-place-des-écrans)
5. [Le Déroulé Pas-à-Pas (Le Scénario en 6 Étapes)](#5-le-déroulé-pas-à-pas-le-scénario-en-6-étapes)
   - [Étape 0 : Le texte en clair (Aucun)](#étape-0--le-texte-en-clair-aucun)
   - [Étape 1 : Chiffrement historique (César)](#étape-1--chiffrement-historique-césar)
   - [Étape 2 : Chiffrement par blocs sans IV (AES-ECB)](#étape-2--chiffrement-par-blocs-sans-iv-aes-ecb)
   - [Étape 3 : Chiffrement chaîné non authentifié (AES-CBC & Malléabilité)](#étape-3--chiffrement-chaîné-non-authentifié-aes-cbc--malléabilité)
   - [Étape 4 : Chiffrement authentifié (AES-GCM & Intégrité)](#étape-4--chiffrement-authentifié-aes-gcm--intégrité)
   - [Étape 5 : L'échange de clés (X25519 & ECDH)](#étape-5--léchange-de-clés-x25519--ecdh)
6. [Ateliers d'attaque complémentaires avec Ève](#6-ateliers-dattaque-complémentaires-avec-ève)
7. [Interception réseau avancée (Wireshark & Burp Suite)](#7-interception-réseau-avancée-wireshark--burp-suite)
8. [Guide de timing & Dépannage live](#8-guide-de-timing--dépannage-live)

---

## 1. Objectifs et concept pédagogique

**Kernel** ressemble à une messagerie moderne pour communauté tech, mais possède une double facette :
- **Chiffrement côté client (End-to-End / Zero-Knowledge)** : le serveur ne reçoit jamais le texte en clair (uniquement l'algorithme, le mode, l'IV, le tag et le ciphertext en hexadécimal).
- **Laboratoire d'expérimentation** : l'administrateur peut faire évoluer l'algorithme en temps réel pour illustrer les failles historiques et l'apparition des standards modernes.
- **Transparence totale (« Coulisses »)** : sous chaque bulle de message, un tiroir dépliable montre les données réelles qui ont transité sur le câble.

> [!IMPORTANT]
> **Cadre éthique :** Cette démonstration s'exécute exclusivement sur un réseau local contrôlé (hotspot Wi-Fi dédié). Les participants doivent être informés que le trafic peut être intercepté à des fins pédagogiques.

> [!TIP]
> **Code Python pour vos camarades :** Le script autonome [`crypto_atelier.py`](../crypto_atelier.py) à la racine contient l'implémentation Python de tous ces algorithmes (César, Vigenère, RC4, DES, AES-ECB/CBC/GCM, ChaCha20, PBKDF2 et X25519) ainsi que des tests d'attaques prêts à l'emploi. Lancez-le directement avec `python crypto_atelier.py`.

---

## 2. Architecture de la démo & Rôles

La démonstration met en scène 3 perspectives complémentaires :

```
             ┌────────────────────────────────────────────────────────┐
             │                     SERVEUR KERNEL                     │
             │           (FastAPI + WebSocket Hub en mémoire)         │
             └──────▲─────────────────────▲────────────────────▲──────┘
                    │                     │                    │
                    │ ws://               │ ws://              │ ws://
                    │                     │                    │
       ┌────────────▼──────────┐   ┌──────▼───────┐   ┌────────▼──────────┐
       │     PARTICIPANTS      │   │  ADMIN / MC  │   │  ATTAQUANT (ÈVE)  │
       │     (Alice & Bob)     │   │              │   │                   │
       │ - UI de chat standard │   │ - Tableau    │   │ - Flux brut temps │
       │ - Panneau Coulisses   │   │   de bord    │   │   réel (hex)      │
       │ - Chiffrement dans le │   │ - Pilote le  │   │ - Interception    │
       │   navigateur          │   │   scénario   │   │ - Modification    │
       │ URL : /app            │   │ URL : /admin │   │ URL : /eve        │
       └───────────────────────┘   └──────────────┘   └───────────────────┘
```

| Rôle | Utilisateur | Mot de passe | Accès | Fonction |
|---|---|---|---|---|
| **Présentateur / MC** | `admin` | `Admin123!` | `/admin` | Contrôle les étapes, change l'algorithme à chaud, réinitialise la session. |
| **Attaquant (Ève)** | `eve` | `Eve123!` | `/eve` | Observe les paquets, retient les messages (MiTM), altère les octets, casse les clés. |
| **Participants** | `alice`, `bob` ou inscrits en direct | (voir seed) | `/app` | Échangent des messages en direct depuis leurs téléphones ou ordinateurs. |

---

## 3. Préparation technique (J - 30 minutes)

### A. Réseau Hotspot
1. Activez le **point d'accès (partage de connexion)** sur votre téléphone ou un routeur de labo.
2. Connectez la machine serveur au point d'accès.
3. Vérifiez l'adresse IPv4 de votre machine sur le réseau local :
   - **Linux** : `hostname -I` (ex: `192.168.43.50`)
   - **macOS** : `ipconfig getifaddr en0`
   - **Windows** : `ipconfig` (rubrique Carte réseau sans fil Wi-Fi)

### B. Pare-feu
Assurez-vous que le port `3000` est accessible par les clients :
```bash
# Linux
sudo ufw allow 3000/tcp
```
*(Sur Windows, autorisez Python dans le pare-feu public/privé si la pop-up apparaît).*

### C. Démarrage du serveur
```bash
# Dans le dossier du projet
source .venv/bin/activate
python run.py
```
Le terminal confirme l'écoute sur `http://0.0.0.0:3000` avec `DEMO_MODE=True`.

---

## 4. Mise en place des écrans

Pour une présentation fluide en public ou en atelier :
- **Vidéoprojecteur (ou Écran 1)** : navigateur partagé avec deux onglets ou fenêtres côte à côte :
  - À gauche : **`/admin`** (connecté en `admin`)
  - À droite : **`/eve`** (connecté en `eve`)
- **Appareil de démonstration (Smartphone ou Écran 2)** :
  - Connecté en `alice` ou `bob` sur `http://<IP-SERVEUR>:3000/app`
- **Le Public** :
  - Flashe un QR Code ou tape l'URL `http://<IP-SERVEUR>:3000/rejoindre` pour créer leur compte en 10 secondes et rejoindre les salons `#général` ou `#entraide`.

---

## 5. Le Déroulé Pas-à-Pas (Le Scénario en 6 Étapes)

Dans l'interface administrateur (`/admin`), la section **Mode présentation** liste les 6 étapes. Utilisez le bouton **Étape suivante** pour faire progresser l'atelier en synchronisant tous les navigateurs en direct.

---

### Étape 0 : Le texte en clair (Aucun)

> **Message clé :** Sans chiffrement, quiconque se trouve sur le trajet réseau ou sur le serveur peut lire l'intégralité des secrets échangés.

1. **Dans `/admin` :**
   - Cliquez sur **Recommencer** pour être à l'étape 0 (`Aucun`).
2. **Dans `/app` (Alice) :**
   - Ouvrez une discussion avec Bob.
   - Envoyez : `Mot de passe du serveur : P@ssw0rd2026!`.
3. **Observation dans `/app` :**
   - Dépliez le tiroir **Coulisses** sous le message.
   - On observe que le `ciphertext` est simplement la conversion directe UTF-8 en hexadécimal (`4d6f7420646520...`).
4. **Observation dans `/eve` :**
   - Le message apparaît instantanément dans le **Flux en direct**.
   - Le texte est lisible en clair par Ève sans aucun effort.

---

### Étape 1 : Chiffrement historique (César)

> **Message clé :** Un chiffrement naïf par substitution monoalphabétique ne protège rien : l'espace de clés est minuscule (25 décalages).

1. **Dans `/admin` :**
   - Cliquez sur **Étape suivante** (passage à `César`).
2. **Dans `/app` :**
   - Alice envoie : `Rejoins-moi derrière la cafétéria à midi`.
   - Bob reçoit le message déchiffré de façon transparente par son navigateur.
   - Sous les coulisses, le chiffré transmis ressemble à : `Uhmrlqv-prm ghuulhuh...`.
3. **Attaque dans `/eve` :**
   - Le chiffré s'est automatiquement pré-rempli dans l'outil **César / Vigenère**.
   - Cliquez sur le bouton **Brute force César**.
   - **Résultat :** Ève teste les 25 décalages en moins d'une milliseconde et identifie immédiatement le texte en clair français parmi les candidats.

---

### Étape 2 : Chiffrement par blocs sans IV (AES-ECB)

> **Message clé :** Le mode ECB (*Electronic Codebook*) découpe le message en blocs indépendants de 16 octets. Deux blocs de texte identiques produisent deux blocs chiffrés strictement identiques, ce qui trahit la structure des données (le fameux « pingouin ECB »).

1. **Dans `/admin` :**
   - Cliquez sur **Étape suivante** (passage à `AES-ECB`).
2. **Dans `/app` :**
   - Alice envoie un message répétitif :  
     `CONFIDENTIEL! CONFIDENTIEL! CONFIDENTIEL! CONFIDENTIEL!`
3. **Attaque dans `/eve` :**
   - Regardez l'outil **Motifs ECB**.
   - Cliquez sur **Analyser les blocs**.
   - **Résultat :** L'outil surligne les blocs hexadécimaux de 32 caractères hex (16 octets) identiques avec les mêmes couleurs et affiche une alerte :
     > *« Motifs répétitifs détectés ! Des blocs identiques révèlent la structure interne sans même connaître la clé. »*

---

### Étape 3 : Chiffrement chaîné non authentifié (AES-CBC & Malléabilité)

> **Message clé :** Le mode CBC résout le problème d'ECB grâce à un vecteur d'initialisation (IV) aléatoire. En revanche, il **ne garantit pas l'intégrité**. Un attaquant en coupure (Man-in-the-Middle) peut altérer des octets sans que le destinataire ne s'en rende compte.

1. **Dans `/admin` :**
   - Cliquez sur **Étape suivante** (passage à `AES-CBC`).
2. **Préparation de l'attaque dans `/eve` :**
   - Dans le bloc **Interception**, cochez la case :  
     ☑ **Retenir les messages au lieu de les relayer**.
3. **Dans `/app` :**
   - Alice envoie à Bob : `Valider virement de 100 EUR pour Alice`.
   - Côté Alice, le message est marqué en attente d'envoi.
4. **Altération dans `/eve` :**
   - Le message est intercepté et apparaît dans la liste **Messages retenus**.
   - Dans le champ d'édition hexadécimal, modifiez quelques octets du milieu du ciphertext (par exemple changez `0` en `f`).
   - Cliquez sur **Modifier + transmettre**.
5. **Résultat surprenant dans `/app` (Bob) :**
   - Bob reçoit le message.
   - Son navigateur déchiffre les données sans lever aucune erreur cryptographique !
   - Le texte affiché est corrompu ou falsifié au niveau des blocs modifiés, mais **aucune alerte d'intégrité n'apparaît** : CBC ne protège pas contre la falsification.

---

### Étape 4 : Chiffrement authentifié (AES-GCM & Intégrité)

> **Message clé :** Le standard moderne AEAD (*Authenticated Encryption with Associated Data*) calcule un tag d'authentification MAC indissociable du ciphertext. Toute altération d'un seul bit entraîne le rejet immédiat du message.

1. **Dans `/admin` :**
   - Cliquez sur **Étape suivante** (passage à `AES-GCM`).
2. **Dans `/eve` :**
   - Laissez la case d'interception cochée.
3. **Dans `/app` :**
   - Alice envoie : `Autorisation définitive accordée`.
4. **Tentative d'altération dans `/eve` :**
   - Modifiez à nouveau 2 caractères hexadécimaux du chiffré retenu.
   - Cliquez sur **Modifier + transmettre**.
5. **Résultat immédiat chez Bob :**
   - Le message n'est pas affiché dans la conversation.
   - Une alerte rouge s'affiche : **`Erreur d'intégrité (GCM/Poly1305) : le message a été altéré en transit !`**.
   - La falsification est mathematically impossible sans la clé secrète.

---

### Étape 5 : L'échange de clés (X25519 & ECDH)

> **Message clé :** Même avec AES-GCM, si la clé est diffusée par le serveur (*broadcast*), n'importe qui sur le réseau (Ève) peut l'intercepter. La cryptographie asymétrique sur courbe elliptique (X25519) permet à deux personnes d'établir un secret partagé sur un canal public sans que personne d'autre ne puisse le déduire.

1. **Le problème (Mode Broadcast) :**
   - Dans `/eve`, pointez la section **Réglages observés** : la clé symétrique complète s'affiche en clair (`clé diffusée : a9b4c...`). Ève pouvait donc tout déchiffrer.
2. **Dans `/admin` :**
   - Cliquez sur **Étape suivante** (passage à `ECDH X25519 + AES-GCM`).
3. **Ce qui se passe en coulisses :**
   - Chaque navigateur génère localement une paire de clés X25519 stockée en `IndexedDB`.
   - Seule la clé publique est envoyée au serveur.
   - Le secret de chiffrement est calculé par échange Diffie-Hellman : `secret = SHA-256(X25519(ma_clé_privée, sa_clé_publique))`.
4. **Observation dans `/eve` :**
   - La clé diffusée indique désormais : `— (non diffusée)`.
   - Le serveur et Ève ne voient passer que des clés publiques et des blobs chiffrés.
   - **Même avec un accès complet à la base de données et aux trames réseau, Ève ne peut plus rien déchiffrer.**

---

## 6. Ateliers d'attaque complémentaires avec Ève

Pour approfondir lors d'une session de questions/réponses ou d'un atelier plus long :

### A. Force brute DES 24 bits (Taille de clé insuffisante)
1. Dans `/admin`, cliquez sur le bouton **Clé DES 24 bits**.
   *(Cela génère une clé DES dont les 5 premiers octets sont fixés à zéro ; seuls les 3 derniers octets soit 24 bits sont aléatoires).*
2. Alice envoie un message chiffré en `DES-CBC`.
3. Dans `/eve`, descendez sur l'outil **Force brute DES (clé réduite 24 bits)** :
   - Les champs `IV` et `ciphertext` sont automatiquement pré-remplis.
   - Cliquez sur **Lancer**.
   - Le navigateur teste plusieurs milliers de combinaisons par seconde.
   - En quelques secondes, la clé exacte et le texte clair apparaissent à l'écran.
   - *Enseignement :* Démontre pourquoi le DES historique (56 bits) et les clés courtes sont obsolètes depuis 1999.

### B. Attaque par réutilisation de nonce (XOR stream ciphers)
1. Deux messages sont chiffrés avec le même flux de clé (mode CTR ou XOR).
2. Dans `/eve` → **Réutilisation de nonce** :
   - Renseignez les deux chiffrés $C_1$ et $C_2$.
   - Cliquez sur **XOR des deux**.
   - Résultat : $C_1 \oplus C_2 = P_1 \oplus P_2$. La clé disparaît complètement de l'équation, permettant d'extraire les clairs.

### C. Démonstration de l'Effet d'avalanche
1. Dans `/eve` → **Effet d'avalanche** :
   - Comparez le chiffré de `Message A` et celui de `Message B` (un seul caractère différent).
   - Cliquez sur **Comparer**.
   - L'outil calcule le pourcentage de bits modifiés : sur un algorithme moderne comme AES ou ChaCha20, la modification d'un seul bit entraîne la modification d'environ **50 % des bits du chiffré**.

---

## 7. Interception réseau avancée (Wireshark & Burp Suite)

Si vous présentez devant un public de spécialistes réseau ou sécurité :

### A. Avec Wireshark
1. Lancez Wireshark sur la machine hôte.
2. Écoutez sur l'interface Wi-Fi / Hotspot (ex: `wlan0` ou `en0`).
3. Appliquez le filtre de capture :
   ```text
   tcp.port == 3000
   ```
4. Envoyez un message depuis un smartphone.
5. Clic droit sur une trame TCP → **Follow** → **TCP Stream** ou **WebSocket Stream** :
   - Vous visualisez les trames JSON envoyées en clair sur le WebSocket (`ws://`).
   - L'absence de TLS permet de montrer exactement ce qui se passe sur la couche 7.

### B. Avec Burp Suite (Proxy Man-in-the-Middle)
1. Dans Burp Suite → **Proxy** → **Proxy Settings** :
   - Ajoutez un listener sur `0.0.0.0:8080`.
   - Dans l'onglet *Request handling*, activez la redirection vers l'hôte `127.0.0.1` et port `3000`.
2. Les participants pointent leur navigateur vers `http://<IP>:8080`.
3. Burp intercepte les trames WebSocket sous **Proxy → WebSockets history**.
4. Vous pouvez modifier les trames à la volée directement dans le Repeater/Interceptor de Burp.

---

## 8. Guide de timing & Dépannage live

### Grille de timing conseillée (Session de 45 minutes)

| Minute | Phase | Action principale |
|---|---|---|
| **00 - 05** | Introduction | Connexion du public au hotspot, ouverture de `/rejoindre`, distribution des rôles. |
| **05 - 12** | Étape 0 & 1 | Texte clair, observation du flux dans `/eve`, cassage express de César. |
| **12 - 20** | Étape 2 | Chiffrement par blocs, explication du pingouin ECB, détection de répétitions. |
| **20 - 30** | Étape 3 & 4 | L'attaque reine : interception MiTM sur CBC (altération acceptée) vs protection GCM (rejet). |
| **30 - 40** | Étape 5 | Problématique de l'échange de clés, bascule sur X25519, vérification de l'aveuglement d'Ève. |
| **40 - 45** | Conclusion / Q&A | Démonstration bonus (DES 24 bits ou avalanche), questions de l'auditoire. |

---

### Dépannage rapide en direct

| Problème rencontré | Cause fréquente | Solution immédiate |
|---|---|---|
| Les téléphones n'accèdent pas à l'adresse IP | L'option **Isolation client (AP Isolation)** est active sur le point d'accès du téléphone. | Utiliser un autre smartphone en hotspot ou partager la connexion via un routeur portable / partage USB. |
| Le port 3000 ne répond pas | Le pare-feu de l'ordinateur bloque les connexions entrantes. | Vérifier avec `sudo ufw allow 3000/tcp` (Linux) ou désactiver temporairement le pare-feu local pour le réseau privé. |
| L'interface semble garder l'ancien algorithme | L'onglet du navigateur a perdu la connexion WebSocket. | L'application se reconnecte automatiquement sous 2 secondes ; si besoin, rafraîchir avec `Ctrl+Maj+R`. |
| Remise à zéro complète après l'atelier | On souhaite repartir d'une base neuve pour la session suivante. | Couper le serveur (`Ctrl+C`), supprimer `kernel.db` et relancer `python run.py`. |

