<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~750 -->
# Cartographie d'Architecture : Kernel

Kernel est une plateforme de messagerie web pour communauté technique, doublée d'un laboratoire interactif de démonstration cryptographique en réseau local (LAN).

---

## 1. Vue d'Ensemble du Système

```
+-------------------------------------------------------------------------+
|                           CLIENT (Navigateur)                           |
|  - Rendu Hybride : SSR (Jinja2) + SPA Conversationnelle                 |
|  - Moteur Crypto Client : Web Crypto API + node-forge + noble-ciphers   |
|  - Gestion des Clés : IndexedDB (privées) + Dérivation PBKDF2 (local)    |
+-------------------------------------------------------------------------+
                       |                       ^
          HTTP (REST)  |                       |  WebSocket (/ws)
        CSRF + Cookies |                       |  Trames JSON bidirectionnelles
                       v                       |
+-------------------------------------------------------------------------+
|                         SERVEUR BACKEND (FastAPI)                       |
|  - ASGI Uvicorn (Monoprocessus)                                         |
|  - CacheControlMiddleware (/static/v-<hash>/ anti-cache navigateur)     |
|  - Sécurité : Argon2id (mots de passe), itsdangerous (sessions signées) |
|  - Hub WebSocket en mémoire (présence, diffusion ciblée)                |
|  - Démo & Interception : EveState (mise en attente / altération MiTM)   |
+-------------------------------------------------------------------------+
                       |                       ^
        SQLAlchemy 2.0 |                       | SessionLocal
                       v                       |
+-------------------------------------------------------------------------+
|                        BASE DE DONNÉES (SQLite)                         |
|  - Fichier : kernel.db (PRAGMA foreign_keys = ON)                       |
|  - Principe Zero-Knowledge : aucun clair stocké (ciphertext hex, iv, tag)|
+-------------------------------------------------------------------------+
```

---

## 2. Découpage Fonctionnel

| Couche | Composants clés | Responsabilité |
|---|---|---|
| **Présentation & UI** | [`app/templates/`](file:///home/admin/Project/kernel/app/templates/), [`static/css/`](file:///home/admin/Project/kernel/static/css/) | Gabarits Jinja2, style responsive 375px/desktop, thèmes clair/sombre. |
| **Logique Client** | [`static/js/app.js`](file:///home/admin/Project/kernel/static/js/app.js), [`static/js/eve.js`](file:///home/admin/Project/kernel/static/js/eve.js) | État conversationnel, flux live Ève, outils d'attaque. |
| **Cryptographie Client** | [`static/js/crypto/`](file:///home/admin/Project/kernel/static/js/crypto/) | Chiffrement E2EE de 13 algorithmes, gestion de clés X25519/PBKDF2. |
| **API & Contrôleurs** | [`app/routes/`](file:///home/admin/Project/kernel/app/routes/) | 15 routeurs REST (auth, messages, salons, groupes, admin, eve, etc.). |
| **Hub Temps Réel** | [`app/ws/hub.py`](file:///home/admin/Project/kernel/app/ws/hub.py), [`app/ws/handlers.py`](file:///home/admin/Project/kernel/app/ws/handlers.py) | Connexions WebSocket, suivi de présence, interception et diffusion ciblée. |
| **Modèles & Données** | [`app/models.py`](file:///home/admin/Project/kernel/app/models.py), [`app/database.py`](file:///home/admin/Project/kernel/app/database.py) | 21 tables SQLAlchemy 2.0, persistance SQLite avec contraintes d'intégrité. |

---

## 3. Flux de Données Typique : Envoi d'un Message Chiffré

```
[ Alice (Expéditeur) ]
   |
   | 1. Saisie texte clair "Bonjour Bob"
   | 2. static/js/crypto/index.js: encrypt(texte, algo, cle)
   |    => Produit { algo, mode, iv, ciphertext_hex, tag, key_fp }
   | 3. Envoi via WebSocket : frame {"type": "chat.send", ...}
   v
[ Serveur FastAPI : ws/handlers.py ]
   |
   | 4. Contrôle d'appartenance à la conversation (is_member)
   | 5. Persistance en base SQLite (Message chiffré uniquement)
   | 6. Hub WebSocket : vérification de l'interception d'Ève
   |    - Si interception inactive : transmission immédiate aux destinataires
   |    - Si interception active   : mise en attente (eve.held), notifie Ève
   v
[ Bob (Destinataire) ]
   |
   | 7. Réception de la trame chiffrée
   | 8. static/js/crypto/index.js: decrypt(frame, cle)
   | 9. Affichage de la bulle déchiffrée + tiroir « Coulisses »
```

