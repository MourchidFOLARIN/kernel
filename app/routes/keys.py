"""Relais des éléments PUBLICS de distribution de clés (étape 4).

- Sel PBKDF2 par conversation (mode password) : public, aléatoire, créé à la demande.
- Clé publique X25519 par utilisateur (mode x25519).
Le serveur ne reçoit JAMAIS ni mot de passe, ni clé dérivée, ni clé privée.
"""
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.chat import is_member, member_ids
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import ConversationMember, ConversationSalt, User, UserPublicKey, now_utc
from app.ws.hub import hub

router = APIRouter(prefix="/api/keys", tags=["keys"])
PUB_RE = re.compile(r"^[0-9a-f]{64}$")


def get_or_create_salt(db: DbSession, conv_id: int) -> str:
    row = db.scalar(select(ConversationSalt).where(ConversationSalt.conversation_id == conv_id))
    if not row:
        row = ConversationSalt(conversation_id=conv_id, salt_hex=secrets.token_hex(16))
        db.add(row)
        db.commit()
    return row.salt_hex


def store_public_key(db: DbSession, user_id: int, pub: str) -> None:
    pub = pub.lower()
    if not PUB_RE.match(pub):
        raise ValueError("clé publique X25519 invalide (32 octets hex)")
    row = db.scalar(select(UserPublicKey).where(UserPublicKey.user_id == user_id))
    if row:
        row.public_key_hex, row.updated_at = pub, now_utc()
    else:
        db.add(UserPublicKey(user_id=user_id, public_key_hex=pub))
    db.commit()


def peers_of(db: DbSession, user_id: int) -> set[int]:
    convs = db.scalars(select(ConversationMember.conversation_id).where(ConversationMember.user_id == user_id))
    out: set[int] = set()
    for cid in convs:
        out.update(member_ids(db, cid))
    out.discard(user_id)
    return out


@router.get("/salt/{conversation_id}")
def salt(conversation_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if not is_member(db, conversation_id, user.id):
        raise HTTPException(403, "Conversation inaccessible.")
    return {"conversation_id": conversation_id, "salt": get_or_create_salt(db, conversation_id)}


class PubIn(BaseModel):
    public_key_hex: str

    @field_validator("public_key_hex")
    @classmethod
    def _v(cls, v: str) -> str:
        if not PUB_RE.match(v.lower()):
            raise ValueError("clé publique invalide")
        return v.lower()


@router.post("/public", dependencies=[Depends(csrf_protect)])
async def publish(data: PubIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    store_public_key(db, user.id, data.public_key_hex)
    await hub.send_to_users(peers_of(db, user.id), {"type": "key.public", "user_id": user.id,
                                                     "public_key_hex": data.public_key_hex})
    return {"ok": True}


@router.get("/public/{user_id}")
def get_public(user_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    row = db.scalar(select(UserPublicKey).where(UserPublicKey.user_id == user_id))
    # 200 + null : pas encore de cle publiee = etat normal (jamais connecte), pas une erreur.
    return {"user_id": user_id, "public_key_hex": row.public_key_hex if row else None}
