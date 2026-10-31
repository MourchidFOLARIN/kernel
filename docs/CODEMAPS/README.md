<!-- Generated: 2026-10-31 | Files scanned: 130 | Token estimate: ~400 -->
# Cartographies d'Architecture (Codemaps) — Kernel

Bienvenue dans la documentation d'architecture condensée de **Kernel**. Ces documents sont conçus pour offrir une vision d'ensemble synthétique et structurée du projet, optimisée à la fois pour les développeurs et pour la consommation par les agents IA.

---

## Sommaire des Cartographies

| Fichier | Sujet couvert |
|---|---|
| **[`architecture.md`](architecture.md)** | Vue d'ensemble du système, frontières applicatives, flux de données d'un message chiffré et principes directeurs. |
| **[`backend.md`](backend.md)** | Chaîne middleware, inventaire complet des 15 routeurs d'API REST, protocole WebSocket (`/ws`) et modules métier. |
| **[`frontend.md`](frontend.md)** | Arborescence des templates Jinja2, modules JavaScript applicatifs, moteur cryptographique client et UX. |
| **[`data.md`](data.md)** | Schéma relationnel de la base SQLite, inventaire des 21 tables SQLAlchemy, cascades d'intégrité et principe Zero-Knowledge. |
| **[`dependencies.md`](dependencies.md)** | Dépendances Python, modules cryptographiques locaux (node-forge, noble), scripts d'audit et outils de test. |

---

## Principes Clés à Retenir

1. **Chiffrement de bout en bout (Zero-Knowledge)** : Le serveur ne reçoit, ne stocke et ne transmet jamais de texte en clair (uniquement le ciphertext hex, l'IV, le tag d'authentification et l'empreinte de clé).
2. **Autonomie totale en réseau local (LAN)** : Zéro appel à des CDN ou services cloud externes.
3. **Monoprocessus avec état mémoire** : Le hub WebSocket et l'état d'interception d'Ève sont maintenus en mémoire vive par l'instance Uvicorn.
4. **Intégrité stricte SQLite** : Les contraintes de clés étrangères sont systématiquement appliquées via `PRAGMA foreign_keys = ON;`.

