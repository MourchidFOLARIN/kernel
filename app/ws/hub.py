"""Hub WebSocket : connexions par utilisateur, présence, diffusion ciblée.

Un utilisateur peut avoir plusieurs onglets ouverts : on garde un ensemble de
sockets par user_id. Tout est en mémoire (un seul processus uvicorn).
"""
import asyncio
import json

from fastapi import WebSocket


class Hub:
    def __init__(self):
        self.connections: dict[int, set[WebSocket]] = {}
        self.lock = asyncio.Lock()

    def online_ids(self) -> set[int]:
        return {uid for uid, socks in self.connections.items() if socks}

    async def connect(self, user_id: int, ws: WebSocket) -> bool:
        """Retourne True si c'est la première connexion (passage en ligne)."""
        async with self.lock:
            socks = self.connections.setdefault(user_id, set())
            first = not socks
            socks.add(ws)
            return first

    async def disconnect(self, user_id: int, ws: WebSocket) -> bool:
        """Retourne True si l'utilisateur n'a plus aucune connexion (hors ligne)."""
        async with self.lock:
            socks = self.connections.get(user_id, set())
            socks.discard(ws)
            if not socks:
                self.connections.pop(user_id, None)
                return True
            return False

    async def send_to_user(self, user_id: int, payload: dict) -> None:
        text = json.dumps(payload, ensure_ascii=False)
        for ws in list(self.connections.get(user_id, ())):
            try:
                await ws.send_text(text)
            except Exception:  # socket morte : nettoyée à la déconnexion
                pass

    async def send_to_users(self, user_ids, payload: dict) -> None:
        for uid in set(user_ids):
            await self.send_to_user(uid, payload)

    async def broadcast(self, payload: dict) -> None:
        await self.send_to_users(list(self.connections), payload)


hub = Hub()


class EveState:
    """État de l'espace attaquant (en mémoire, un seul processus).

    - attackers : user_id des sockets Ève connectés (reçoivent le flux eve.raw).
    - intercept : si True, les messages sont RETENUS au lieu d'être relayés.
    - held      : messages en attente, par id technique, modifiables par Ève.
    """
    def __init__(self):
        self.attackers: set[int] = set()
        self.intercept: bool = False
        self.held: dict[str, dict] = {}
        self._seq = 0

    def next_hold_id(self) -> str:
        self._seq += 1
        return f"h{self._seq}"


eve = EveState()


async def eve_feed(hub: "Hub", payload: dict) -> None:
    """Diffuse une trame au flux Ève (toutes les connexions attaquant)."""
    for uid in list(eve.attackers):
        await hub.send_to_user(uid, payload)
