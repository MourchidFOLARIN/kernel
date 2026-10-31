"""API REST de la messagerie : conversations DM, historique, envoi (secours/tests), lecture."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from app.chat import (ChatError, enrich, find_or_create_dm, history, list_conversations, member_ids,
                      message_out, record_receipt, save_message)
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import User
from app.ws.delivery import deliver_to_recipients
from app.ws.hub import hub

router = APIRouter(prefix="/api", tags=["messages"])

HTTP_CODES = {"forbidden": 403, "not_found": 404, "validation": 400}


def _raise(e: ChatError):
    raise HTTPException(HTTP_CODES.get(e.code, 400), e.message)


class DmIn(BaseModel):
    user_id: int


class SendIn(BaseModel):
    algo: str = "Aucun"
    mode: str = "clair"
    iv: str = ""
    ciphertext: str = Field(min_length=2, max_length=16000)
    tag: str = ""
    reply_to: int | None = None
    key_dist: str | None = None
    key_fp: str | None = None
    client_id: str | None = None
    attachment: dict | None = None


@router.get("/conversations")
def conversations(db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    return list_conversations(db, user, hub.online_ids())


@router.post("/conversations/dm", dependencies=[Depends(csrf_protect)])
def open_dm(data: DmIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    try:
        conv = find_or_create_dm(db, user, data.user_id)
    except ChatError as e:
        _raise(e)
    return {"id": conv.id, "kind": conv.kind}


@router.get("/messages/{conversation_id}")
def get_history(conversation_id: int, before: int | None = None,
                db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    try:
        return history(db, user, conversation_id, before)
    except ChatError as e:
        _raise(e)


@router.post("/messages/{conversation_id}", dependencies=[Depends(csrf_protect)])
async def send(conversation_id: int, data: SendIn, db: DbSession = Depends(get_db),
               user: User = Depends(require_user)):
    """Envoi par REST (secours si le WebSocket est coupé). Relayé en temps réel."""
    try:
        msg = save_message(db, user, {**data.model_dump(), "conversation_id": conversation_id})
    except ChatError as e:
        _raise(e)
    payload = enrich(db, msg, message_out(msg, client_id=data.client_id))
    recipients = [m for m in member_ids(db, conversation_id) if m != user.id]
    result = await deliver_to_recipients(payload, user.username, recipients)
    return {**payload, "status": "sent", "held": result["held"]}


@router.post("/messages/{message_id}/read", dependencies=[Depends(csrf_protect)])
async def mark_read(message_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    try:
        res = record_receipt(db, user, message_id, "read")
    except ChatError as e:
        _raise(e)
    if res and res[0].sender_id:
        for mid in res[1]:
            await hub.send_to_user(res[0].sender_id, {"type": "receipt", "message_id": mid,
                                                      "conversation_id": res[0].conversation_id,
                                                      "user_id": user.id, "status": "read"})
    return {"ok": True}


class EditIn(BaseModel):
    algo: str = "Aucun"
    mode: str = "clair"
    iv: str = ""
    ciphertext: str = Field(min_length=2, max_length=16000)
    tag: str = ""
    key_dist: str | None = None
    key_fp: str | None = None


class ReactionIn(BaseModel):
    emoji: str = Field(min_length=1, max_length=16)


@router.patch("/messages/{message_id}", dependencies=[Depends(csrf_protect)])
async def edit_message(message_id: int, data: EditIn, db: DbSession = Depends(get_db),
                       user: User = Depends(require_user)):
    from app.models import Message, now_utc
    from app.chat import enrich, is_member, message_out
    msg = db.get(Message, message_id)
    if not msg or msg.deleted_at:
        raise HTTPException(404, "Message introuvable.")
    if msg.sender_id != user.id:
        raise HTTPException(403, "Vous ne pouvez modifier que vos messages.")
    if not is_member(db, msg.conversation_id, user.id):
        raise HTTPException(403)
    from app.chat import ALLOWED_ALGOS, HEX_RE, MAX_HEX
    if data.algo not in ALLOWED_ALGOS:
        raise HTTPException(400, "algo non supporté.")
    ct = data.ciphertext
    if not ct or len(ct) > MAX_HEX or len(ct) % 2 or not HEX_RE.match(ct):
        raise HTTPException(400, "ciphertext invalide.")
    msg.algo, msg.mode = data.algo, data.mode
    msg.iv_hex = data.iv or None
    msg.ciphertext_hex = data.ciphertext.lower()
    msg.tag_hex = data.tag or None
    msg.key_dist, msg.key_fp = data.key_dist, data.key_fp
    msg.edited_at = now_utc()
    db.commit()
    payload = enrich(db, msg, message_out(msg))
    payload["type"] = "chat.edited"
    await hub.send_to_users(member_ids(db, msg.conversation_id), payload)
    return payload


@router.delete("/messages/{message_id}", dependencies=[Depends(csrf_protect)])
async def delete_message(message_id: int, db: DbSession = Depends(get_db),
                         user: User = Depends(require_user)):
    from app.models import Message, now_utc
    from app.chat import is_member
    msg = db.get(Message, message_id)
    if not msg or msg.deleted_at:
        raise HTTPException(404)
    if msg.sender_id != user.id:
        raise HTTPException(403, "Vous ne pouvez supprimer que vos messages.")
    if not is_member(db, msg.conversation_id, user.id):
        raise HTTPException(403)
    msg.deleted_at = now_utc()
    msg.ciphertext_hex = ""
    msg.iv_hex = None
    msg.tag_hex = None
    db.commit()
    payload = {"type": "chat.deleted", "id": msg.id, "conversation_id": msg.conversation_id}
    await hub.send_to_users(member_ids(db, msg.conversation_id), payload)
    return {"ok": True}


@router.post("/messages/{message_id}/reactions", dependencies=[Depends(csrf_protect)])
async def toggle_reaction(message_id: int, data: ReactionIn, db: DbSession = Depends(get_db),
                          user: User = Depends(require_user)):
    from app.models import Message, MessageReaction
    from app.chat import is_member, reactions_of
    msg = db.get(Message, message_id)
    if not msg or msg.deleted_at or not is_member(db, msg.conversation_id, user.id):
        raise HTTPException(404)
    existing = db.scalar(select(MessageReaction).where(
        MessageReaction.message_id == message_id, MessageReaction.user_id == user.id,
        MessageReaction.emoji == data.emoji))
    if existing:
        db.delete(existing)
    else:
        db.add(MessageReaction(message_id=message_id, user_id=user.id, emoji=data.emoji))
    db.commit()
    rx = reactions_of(db, message_id)
    payload = {"type": "chat.reaction", "message_id": message_id,
               "conversation_id": msg.conversation_id, "reactions": rx}
    await hub.send_to_users(member_ids(db, msg.conversation_id), payload)
    return payload


@router.get("/attachments/{att_id}")
def get_attachment(att_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    from app.models import Attachment, Message
    from app.chat import is_member
    att = db.get(Attachment, att_id)
    if not att:
        raise HTTPException(404)
    msg = db.get(Message, att.message_id)
    if not msg or not is_member(db, msg.conversation_id, user.id):
        raise HTTPException(403)
    return {"id": att.id, "algo": att.algo, "iv": att.iv_hex or "", "ciphertext": att.ciphertext_hex,
            "tag": att.tag_hex or "", "size": att.size, "message_id": att.message_id}
