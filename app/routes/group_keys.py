"""Distribution de clé de groupe (salons / groupes privés) en mode X25519.

Approche simple documentée :
- Une clé de groupe aléatoire (32 octets) est générée côté navigateur.
- Pour chaque membre, elle est chiffrée (AES-GCM) avec la clé de session X25519
  pair-à-pair (SHA-256(ECDH(moi, destinataire))) — même mécanique que les DM.
- Le serveur stocke/relaye uniquement ces emballages (jamais la clé de groupe).
- Mode password : le sel de conversation (déjà en place) sert pour TOUTE la conversation
  (DM, salon ou groupe) — tous les membres saisissent le même code.
- Mode broadcast : inchangé (clé globale).
Limite X25519 groupes : un membre sans paire / nouvel appareil doit recevoir un
nouvel emballage ; sinon « impossible à déchiffrer ».
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.chat import is_member, member_ids
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import GroupKeyWrap, User
from app.ws.hub import hub

router = APIRouter(prefix="/api/group-keys", tags=["group-keys"])


class WrapIn(BaseModel):
    conversation_id: int
    key_fp: str = Field(min_length=8, max_length=16)
    recipient_id: int
    iv: str
    ciphertext: str
    tag: str


@router.post("", dependencies=[Depends(csrf_protect)])
async def publish_wrap(data: WrapIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if not is_member(db, data.conversation_id, user.id):
        raise HTTPException(403)
    if not is_member(db, data.conversation_id, data.recipient_id):
        raise HTTPException(400, "Destinataire non membre.")
    existing = db.scalar(select(GroupKeyWrap).where(
        GroupKeyWrap.conversation_id == data.conversation_id,
        GroupKeyWrap.key_fp == data.key_fp,
        GroupKeyWrap.recipient_id == data.recipient_id))
    if existing:
        existing.iv_hex, existing.ciphertext_hex, existing.tag_hex = data.iv, data.ciphertext, data.tag
        existing.sender_id = user.id
    else:
        db.add(GroupKeyWrap(conversation_id=data.conversation_id, key_fp=data.key_fp,
                            sender_id=user.id, recipient_id=data.recipient_id,
                            iv_hex=data.iv, ciphertext_hex=data.ciphertext, tag_hex=data.tag))
    db.commit()
    await hub.send_to_user(data.recipient_id, {
        "type": "group.key", "conversation_id": data.conversation_id, "key_fp": data.key_fp,
        "sender_id": user.id, "iv": data.iv, "ciphertext": data.ciphertext, "tag": data.tag})
    return {"ok": True}


@router.get("/{conversation_id}")
def list_wraps(conversation_id: int, db: DbSession = Depends(get_db),
               user: User = Depends(require_user)):
    if not is_member(db, conversation_id, user.id):
        raise HTTPException(403)
    rows = db.scalars(select(GroupKeyWrap).where(
        GroupKeyWrap.conversation_id == conversation_id,
        GroupKeyWrap.recipient_id == user.id)).all()
    return [{"key_fp": r.key_fp, "sender_id": r.sender_id, "iv": r.iv_hex,
             "ciphertext": r.ciphertext_hex, "tag": r.tag_hex} for r in rows]
