"""Endpoint WebSocket /ws et traitement des trames.

Client → serveur : chat.send, typing, receipt
Serveur → client : chat.message, presence (+ presence.list à la connexion),
                   typing, receipt, error

Authentification par le cookie de session HttpOnly existant. Aucune
vérification Host/Origin (compatible proxy Burp en ws:// simple).
"""
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.chat import ChatError, enrich, is_member, member_ids, message_out, record_receipt, save_message
from app.database import SessionLocal
from app import config
from app.demo import get_settings, settings_payload
from app.models import now_utc
from app.security import get_session
from app.ws.hub import eve, eve_feed, hub

router = APIRouter()
MAX_FRAME = 64_000


async def _error(ws: WebSocket, code: str, message: str, client_id: str | None = None):
    out = {"type": "error", "code": code, "message": message}
    if client_id:
        out["client_id"] = client_id
    await ws.send_json(out)


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    db = SessionLocal()
    try:
        sess = get_session(db, ws)  # WebSocket expose .cookies comme Request
        if not sess:
            await ws.accept()
            await ws.close(code=4401)
            return
        user = sess.user
        user_id = user.id
    finally:
        db.close()

    is_attacker = config.DEMO_MODE and user.role == "attaquant"
    await ws.accept()
    first = await hub.connect(user_id, ws)
    if is_attacker:
        eve.attackers.add(user_id)
    await ws.send_json({"type": "presence.list", "online": sorted(hub.online_ids())})
    # Réglages démo (algo + clé broadcast) — faille volontaire étape 3
    db2 = SessionLocal()
    try:
        await ws.send_json(settings_payload(get_settings(db2)))
    finally:
        db2.close()
    if first:
        await hub.broadcast({"type": "presence", "user_id": user_id, "online": True})
    try:
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_FRAME:
                await _error(ws, "validation", "Trame trop volumineuse.")
                continue
            try:
                frame = json.loads(raw)
                assert isinstance(frame, dict)
            except Exception:
                await _error(ws, "validation", "JSON invalide.")
                continue
            await handle_frame(ws, user_id, frame)
    except WebSocketDisconnect:
        pass
    finally:
        gone = await hub.disconnect(user_id, ws)
        if gone:
            eve.attackers.discard(user_id)
            await hub.broadcast({"type": "presence", "user_id": user_id, "online": False})


def _cid(frame) -> str | None:
    if isinstance(frame, dict) and frame.get("type") == "chat.send":
        return str(frame.get("client_id") or "")[:64] or None
    return None


async def handle_frame(ws: WebSocket, user_id: int, frame: dict) -> None:
    kind = frame.get("type")
    db = SessionLocal()
    try:
        from app.models import User
        user = db.get(User, user_id)
        if not user or user.is_suspended:
            await _error(ws, "forbidden", "Compte indisponible.")
            return
        if kind == "chat.send":
            msg = save_message(db, user, frame)
            client_id = str(frame.get("client_id") or "")[:64] or None
            payload = enrich(db, msg, message_out(msg, client_id=client_id))
            members = member_ids(db, msg.conversation_id)
            recipients = [m for m in members if m != user_id]
            # Expéditeur : toujours son propre écho (statut « sent »).
            await hub.send_to_user(user_id, {**payload, "status": "sent"})
            from app.ws.delivery import deliver_to_recipients
            await deliver_to_recipients(payload, user.username, recipients)
        elif kind == "typing":
            conv_id = int(frame.get("conversation_id") or 0)
            if not is_member(db, conv_id, user_id):
                raise ChatError("forbidden", "Conversation inaccessible.")
            await hub.send_to_users([m for m in member_ids(db, conv_id) if m != user_id], {
                "type": "typing", "conversation_id": conv_id, "user_id": user_id,
                "active": bool(frame.get("active"))})
        elif kind == "receipt":
            status = frame.get("status")
            res = record_receipt(db, user, int(frame.get("message_id") or 0), status)
            if res:
                msg, marked = res
                if marked and msg.sender_id:
                    for mid in marked:
                        await hub.send_to_user(msg.sender_id, {
                            "type": "receipt", "message_id": mid, "conversation_id": msg.conversation_id,
                            "user_id": user_id, "status": status})
                if status == "read":
                    # Synchronise les autres onglets du lecteur (badge non lus).
                    await hub.send_to_user(user_id, {"type": "read.sync",
                                                     "conversation_id": msg.conversation_id})
        elif kind == "key.public":
            # Publication de MA clé publique X25519 → relayée à mes correspondants.
            from app.routes.keys import peers_of, store_public_key
            pub = str(frame.get("public_key_hex") or "").lower()
            store_public_key(db, user_id, pub)
            await hub.send_to_users(peers_of(db, user_id), {
                "type": "key.public", "user_id": user_id, "public_key_hex": pub})
        elif kind == "key.request":
            # Demande de la clé publique d'un autre membre.
            from app.models import UserPublicKey
            from sqlalchemy import select
            target = int(frame.get("user_id") or 0)
            row = db.scalar(select(UserPublicKey).where(UserPublicKey.user_id == target))
            if row:
                await ws.send_json({"type": "key.public", "user_id": target,
                                    "public_key_hex": row.public_key_hex})
            else:
                await _error(ws, "key_missing", "Aucune clé publique pour ce membre.")
        elif kind in ("eve.intercept", "eve.forward", "eve.reject", "eve.modify"):
            if not (config.DEMO_MODE and user.role == "attaquant"):
                await _error(ws, "forbidden", "Réservé à l'attaquant.")
            else:
                await handle_eve(ws, user, frame)
        else:
            await _error(ws, "validation", f"Type de trame inconnu : {kind!r}")
    except ChatError as e:
        await _error(ws, e.code, e.message, _cid(frame))
    except (TypeError, ValueError):
        await _error(ws, "validation", "Champs invalides.", _cid(frame))
    finally:
        db.close()


async def handle_eve(ws, user, frame: dict) -> None:
    kind = frame.get("type")
    if kind == "eve.intercept":
        eve.intercept = bool(frame.get("active"))
        await eve_feed(hub, {"type": "eve.mode", "intercept": eve.intercept})
        return
    hid = str(frame.get("hold_id") or "")
    held = eve.held.get(hid)
    if kind == "eve.reject":
        if held:
            eve.held.pop(hid, None)
            await eve_feed(hub, {"type": "eve.resolved", "hold_id": hid, "action": "reject"})
        return
    if kind in ("eve.modify", "eve.forward"):
        if not held:
            await _error(ws, "not_found", "Message retenu introuvable.")
            return
        payload = dict(held["payload"])
        new_hex = frame.get("ciphertext")
        if kind == "eve.modify" and isinstance(new_hex, str):
            cleaned = new_hex.strip().lower()
            import re as _re
            if cleaned and (len(cleaned) % 2 or not _re.fullmatch(r"[0-9a-f]*", cleaned)):
                await _error(ws, "validation", "Chiffré modifié invalide (hex).")
                return
            payload["ciphertext"] = cleaned
            payload["tampered"] = True
        await hub.send_to_users(held["recipients"], payload)
        eve.held.pop(hid, None)
        await eve_feed(hub, {"type": "eve.resolved", "hold_id": hid,
                             "action": "forward", "tampered": payload.get("tampered", False)})
