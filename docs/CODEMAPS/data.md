<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~850 -->
# Cartographie des Données : Kernel

Kernel persiste son état dans une base SQLite locale (`kernel.db`). Le serveur applique le principe **Zero-Knowledge** : aucun contenu de message n'est jamais stocké en texte clair.

---

## 1. Schéma Général & Relations

```
       [ User ] 1 ─── * [ Session ] (token_hash, csrf_token)
          │     1 ─── * [ UserSkill ] & [ UserLink ]
          │     1 ─── * [ Contact ] (from_id, to_id, status)
          │     1 ─── * [ UserPublicKey ] (public_key_hex X25519)
          │
          │ 1
          │
          * N
 [ ConversationMember ]
          * N
          │
          │ 1
   [ Conversation ] 1 ─── * [ Message ]
   (dm, group, room)           │
                               ├── 1 ─── * [ MessageReaction ] (emoji)
                               ├── 1 ─── * [ MessageReceipt ] (delivered, read)
                               └── 1 ─── * [ Attachment ] (blob chiffré)
```

---

## 2. Inventaire des 21 Tables SQLite

| Table | Clé Primaire | Clés Étrangères & Cascades | Rôle & Invariants |
|---|---|---|---|
| **`users`** | `id` | — | Comptes membres, admin et attaquant (`role`, `password_hash` Argon2id). |
| **`sessions`** | `id` | `user_id` ➔ `users.id` (CASCADE) | Sessions authentifiées actives (`token_hash` SHA-256 unique, `csrf_token`). |
| **`user_skills`** | `id` | `user_id` ➔ `users.id` (CASCADE) | Compétences déclarées par les membres (ex: `python`, `pentest`, `react`). |
| **`user_links`** | `id` | `user_id` ➔ `users.id` (CASCADE) | Liens externes des membres (GitHub, portfolio). |
| **`login_attempts`**| `id` | — | Journal des tentatives de connexion pour le rate-limiting (IP + pseudo). |
| **`password_reset_codes`** | `id` | `user_id` ➔ `users.id` (CASCADE) | Codes temporaires de réinitialisation de mot de passe (valables 15 min). |
| **`contacts`** | `id` | `from_id`, `to_id` ➔ `users.id` (CASCADE) | Relations d'amis, demandes en attente et blocages (`pending`, `accepted`, `blocked`). |
| **`conversations`** | `id` | `created_by` ➔ `users.id` (SET NULL) | Canaux de discussion (`dm` privé, `group` à plusieurs, ou `room` publique). |
| **`conversation_members`** | `id` | `conversation_id` ➔ `conversations.id` (CASCADE)<br>`user_id` ➔ `users.id` (CASCADE) | Table d'association membres ↔ conversations avec horodatage de lecture. |
| **`messages`** | `id` | `conversation_id` ➔ `conversations.id` (CASCADE)<br>`sender_id` ➔ `users.id` (SET NULL)<br>`reply_to_id` ➔ `messages.id` (SET NULL) | **Zéro clair !** Colonnes : `algo`, `mode`, `iv_hex`, `ciphertext_hex`, `tag_hex`, `key_dist`, `key_fp`. |
| **`message_reactions`** | `id` | `message_id` ➔ `messages.id` (CASCADE)<br>`user_id` ➔ `users.id` (CASCADE) | Réactions émojis déposées sur un message spécifique. |
| **`message_receipts`** | `id` | `message_id` ➔ `messages.id` (CASCADE)<br>`user_id` ➔ `users.id` (CASCADE) | Accusés d'acheminement et de lecture (`delivered`, `read`). |
| **`attachments`** | `id` | `message_id` ➔ `messages.id` (CASCADE) | Fichiers joints chiffrés côté client (taille ≤ ~700 Ko). |
| **`events`** | `id` | `created_by` ➔ `users.id` (SET NULL) | Ateliers et événements communautaires affichés sur `/evenements`. |
| **`contact_messages`** | `id` | — | Messages envoyés via le formulaire de contact public `/contact`. |
| **`reports`** | `id` | `reporter_id` ➔ `users.id` (SET NULL) | Signalements d'abus examinés dans `/admin`. |
| **`demo_settings`** | `id=1` | — | Singleton piloté par l'admin : algorithme courant, mode, distribution et clé broadcast. |
| **`activity_log`** | `id` | `actor_id` ➔ `users.id` (SET NULL) | Piste d'audit des actions administratives et de sécurité. |
| **`user_public_keys`** | `id` | `user_id` ➔ `users.id` (CASCADE) | Clé publique Curve25519 (X25519, 32 octets hex) pour l'échange ECDH. |
| **`conversation_salts`** | `id` | `conversation_id` ➔ `conversations.id` (CASCADE) | Sel public (32 octets hex) pour la dérivation PBKDF2 en mode mot de passe. |
| **`group_key_wraps`** | `id` | `conversation_id` ➔ `conversations.id` (CASCADE)<br>`sender_id`, `recipient_id` ➔ `users.id` (CASCADE) | Clé symétrique de salon emballée en AES-GCM pour chaque membre du groupe. |

---

## 3. Gestion de l'Intégrité & Migrations

- **Intégrité référentielle** : assurée à chaque connexion par le listener SQLAlchemy exécutant `PRAGMA foreign_keys = ON;`.
- **Migrations légères (`_migrate()` dans `app/database.py`)** : vérifie la présence des colonnes récentes (ex: `key_dist`, `key_fp`) et exécute un `ALTER TABLE ADD COLUMN` si nécessaire, garantissant la compatibilité des bases existantes sans outil externe lourd.
- **Peuplement initial (`app/seed.py`)** : création automatique et idempotente des 4 comptes de démonstration (`admin`, `eve`, `alice`, `bob`) et des 10 salons thématiques (#général, #python, #cybersécurité, etc.).

