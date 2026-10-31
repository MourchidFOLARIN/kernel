<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~850 -->
# Cartographie Backend : Kernel

Le backend est bâti avec **FastAPI**, **Uvicorn**, **SQLAlchemy 2.0** et gère à la fois le routage REST et le streaming temps réel bidirectionnel par WebSocket.

---

## 1. Chaîne Middleware & Cycle de Requête

```
Requête HTTP / WS
       │
       ▼
[ CacheControlMiddleware (app/assets.py) ]
  ├── Réécriture d'URL : /static/v-<hash>/... -> /static/...
  └── En-têtes : Cache-Control: no-cache (assets) ou no-store (HTML)
       │
       ▼
[ Dépendances & Sécurité (app/deps.py, app/security.py) ]
  ├── get_db : SessionLocal SQLite
  ├── current_session / current_user : cookie signé kernel_session
  ├── require_admin / require_attacker : contrôle de rôle
  └── csrf_protect : validation double-soumission / token signé
       │
       ▼
[ Routeur FastAPI / Handler WebSocket ]
```

---

## 2. Inventaire des Routes REST

| Préfixe | Fichier | Routes principales | Rôle |
|---|---|---|---|
| `/` | [`app/routes/pages.py`](file:///home/admin/Project/kernel/app/routes/pages.py) | `GET /`, `/fonctionnalites`, `/communautes`, `/dev`, `/cybersecurite`, `/evenements`, `/a-propos`, `/faq`, `/contact`, `/regles`, `/confidentialite`, `/app`, `/rejoindre`, `/connexion` | Rendu SSR des pages publiques et des espaces membres. |
| `/api/auth` | [`app/routes/auth.py`](file:///home/admin/Project/kernel/app/routes/auth.py) | `POST /register`, `/login`, `/logout`, `/forgot`, `/reset` | Inscription, connexion, déconnexion, réinitialisation de mot de passe (Argon2id). |
| `/api` | [`app/routes/messages.py`](file:///home/admin/Project/kernel/app/routes/messages.py) | `GET /conversations`, `POST /conversations/dm`<br>`GET /messages/{conv_id}`, `POST /messages/{conv_id}`<br>`PATCH /messages/{id}`, `DELETE /messages/{id}`<br>`POST /messages/{id}/read`, `POST /messages/{id}/reactions` | Historique, envoi REST de secours, accusés de lecture, réactions et suppression. |
| `/api/rooms` | [`app/routes/rooms.py`](file:///home/admin/Project/kernel/app/routes/rooms.py) | `GET /rooms`, `POST /rooms/{id}/join`, `POST /rooms/{id}/leave` | Liste et adhésion aux salons thématiques publics. |
| `/api/groups` | [`app/routes/groups.py`](file:///home/admin/Project/kernel/app/routes/groups.py) | `GET /groups`, `POST /groups` | Création et consultation des groupes privés à plusieurs membres. |
| `/api/contacts` | [`app/routes/contacts.py`](file:///home/admin/Project/kernel/app/routes/contacts.py) | `GET /contacts`, `POST /contacts/request`, `POST /contacts/{id}/accept`, `POST /contacts/{id}/block`, `DELETE /contacts/{id}` | Gestion des demandes de contacts, amis et blocages. |
| `/api/keys` | [`app/routes/keys.py`](file:///home/admin/Project/kernel/app/routes/keys.py) | `POST /keys/public`, `GET /keys/request/{id}`, `GET /keys/salt/{id}` | Relais de clés publiques X25519 et des sels de dérivation PBKDF2. |
| `/api/group-keys` | [`app/routes/group_keys.py`](file:///home/admin/Project/kernel/app/routes/group_keys.py) | `GET /group-keys/{conv_id}`, `POST /group-keys/{conv_id}` | Distribution des clés de salons emballées par chiffrement asymétrique. |
| `/api/admin` | [`app/routes/admin.py`](file:///home/admin/Project/kernel/app/routes/admin.py) | `GET /admin`, `GET/PUT /admin/demo`, `POST /admin/demo/new-key`<br>`POST /admin/demo/presentation/next`, `POST /admin/demo/presentation/reset`<br>`GET /admin/users`, `POST /admin/users/{id}/role` | Tableau de bord admin, pilotage du scénario de présentation et modération. |
| `/api/eve` | [`app/routes/eve.py`](file:///home/admin/Project/kernel/app/routes/eve.py) | `GET /eve`, `GET /api/eve/settings`, `GET /api/eve/recent` | Interface de l'attaquant (accès restreint si `DEMO_MODE=true`). |
| `/api/account` | [`app/routes/account.py`](file:///home/admin/Project/kernel/app/routes/account.py) | `POST /account/password`, `DELETE /account`, `POST /account/avatar`, `PUT /account/skills` | Profil utilisateur, avatar (512 Ko max) et suppression de compte. |
| `/api/reports` | [`app/routes/reports.py`](file:///home/admin/Project/kernel/app/routes/reports.py) | `POST /reports` | Signalement de messages ou de membres abusifs. |
| `/api/users` | [`app/routes/users.py`](file:///home/admin/Project/kernel/app/routes/users.py) | `GET /users/all`, `GET /users/directory` | Annuaire global des membres et recherche par pseudo/compétence. |

---

## 3. Protocole WebSocket (`/ws`)

- **Point d'entrée** : [`app/ws/handlers.py`](file:///home/admin/Project/kernel/app/ws/handlers.py) (`websocket_endpoint`)
- **Hub central** : [`app/ws/hub.py`](file:///home/admin/Project/kernel/app/ws/hub.py) (Classe `Hub` : suivi des sockets par `user_id`, état `online_ids()`)

### Trames Client ➔ Serveur
- `chat.send` : envoi de message chiffré (`conversation_id`, `algo`, `ciphertext`, `iv`, `tag`).
- `typing` : indicateur de frappe en cours (`conversation_id`, `active: bool`).
- `receipt` : accusé de remise ou lecture (`message_id`, `status: delivered|read`).
- `key.public` : publication d'une clé publique X25519.
- `key.request` : demande de clé publique d'un correspondant.
- `eve.intercept`, `eve.forward`, `eve.reject`, `eve.modify` : commandes MiTM d'Ève.

### Trames Serveur ➔ Client
- `presence.list` / `presence` : synchronisation temps réel des membres connectés.
- `demo.settings` : diffusion de l'algorithme actif et de la clé (en mode broadcast).
- `chat.message` / `chat.edited` / `chat.deleted` / `chat.reaction` : synchronisation du flux de messages.
- `eve.raw` / `eve.held` / `eve.resolved` : flux d'espionnage et de retenue transmis à Ève.

---

## 4. Modules Métier Principaux

- **[`app/chat.py`](file:///home/admin/Project/kernel/app/chat.py)** : Sauvegarde, validation hexadécimale, enrichissement, pagination d'historique et gestion des membres.
- **[`app/security.py`](file:///home/admin/Project/kernel/app/security.py)** : Sessions signées (itsdangerous), hachage de mot de passe (Argon2id), protection CSRF, limitation de débit (rate-limiting IP/pseudo).
- **[`app/demo.py`](file:///home/admin/Project/kernel/app/demo.py)** : Singleton de configuration de la démo (`DemoSettings`), étapes de la présentation de 0 à 5, bascule de sécurité `DEMO_MODE`.
- **[`app/ws/delivery.py`](file:///home/admin/Project/kernel/app/ws/delivery.py)** : Routage des messages avec vérification de l'interception active d'Ève.

