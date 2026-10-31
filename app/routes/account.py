"""Paramètres du compte : mot de passe, suppression, avatar, compétences."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import (ActivityLog, Contact, ConversationMember, Message, Session,
                        User, UserLink, UserSkill)
from app.schemas import ProfileUpdate
from app.security import hash_password, verify_password

router = APIRouter(prefix="/api/account", tags=["account"])

AVATAR_DIR = config.BASE_DIR / "static" / "uploads" / "avatars"
AVATAR_DIR.mkdir(parents=True, exist_ok=True)
MAX_AVATAR = 512_000


class PasswordChange(BaseModel):
    current: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _pw(cls, v: str) -> str:
        if not (re.search(r"[A-Za-z]", v) and re.search(r"\d", v)):
            raise ValueError("Le mot de passe doit contenir une lettre et un chiffre.")
        return v


class SkillsIn(BaseModel):
    skills: list[str] = []


class LinksIn(BaseModel):
    github: str = ""
    portfolio: str = ""


@router.post("/password", dependencies=[Depends(csrf_protect)])
def change_password(data: PasswordChange, db: DbSession = Depends(get_db),
                    user: User = Depends(require_user)):
    if not verify_password(user.password_hash, data.current):
        raise HTTPException(400, "Mot de passe actuel incorrect.")
    user.password_hash = hash_password(data.new_password)
    db.add(ActivityLog(actor_id=user.id, action="compte.mdp", detail_json="{}"))
    db.commit()
    return {"ok": True}


@router.delete("", dependencies=[Depends(csrf_protect)])
def delete_account(db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if user.role == "admin":
        raise HTTPException(400, "Le compte admin ne peut pas être auto-supprimé.")
    uid = user.id
    db.execute(delete(Session).where(Session.user_id == uid))
    db.execute(delete(Contact).where((Contact.from_id == uid) | (Contact.to_id == uid)))
    db.execute(delete(ConversationMember).where(ConversationMember.user_id == uid))
    db.execute(delete(UserSkill).where(UserSkill.user_id == uid))
    db.execute(delete(UserLink).where(UserLink.user_id == uid))
    # Anonymise les messages plutôt que de casser l'historique des autres.
    for m in db.scalars(select(Message).where(Message.sender_id == uid)):
        m.sender_id = None
    db.delete(user)
    db.commit()
    return {"ok": True}


@router.post("/avatar", dependencies=[Depends(csrf_protect)])
async def upload_avatar(file: UploadFile = File(...), db: DbSession = Depends(get_db),
                        user: User = Depends(require_user)):
    if file.content_type not in ("image/png", "image/jpeg", "image/webp", "image/gif"):
        raise HTTPException(400, "Format d'image non supporté.")
    data = await file.read()
    if len(data) > MAX_AVATAR:
        raise HTTPException(400, "Image trop volumineuse (max 512 Ko).")
    ext = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "image/gif": "gif"}[file.content_type]
    path = AVATAR_DIR / f"{user.id}.{ext}"
    path.write_bytes(data)
    user.avatar_path = f"/static/uploads/avatars/{user.id}.{ext}"
    db.commit()
    return {"ok": True, "avatar": user.avatar_path}


@router.put("/skills", dependencies=[Depends(csrf_protect)])
def set_skills(data: SkillsIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    db.execute(delete(UserSkill).where(UserSkill.user_id == user.id))
    for tag in data.skills[:20]:
        tag = tag.strip().lower()[:32]
        if tag:
            db.add(UserSkill(user_id=user.id, tag=tag))
    db.commit()
    return {"ok": True, "skills": [s.tag for s in user.skills]}


@router.put("/links", dependencies=[Depends(csrf_protect)])
def set_links(data: LinksIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    db.execute(delete(UserLink).where(UserLink.user_id == user.id))
    for kind, url in (("github", data.github), ("portfolio", data.portfolio)):
        url = url.strip()
        if url:
            if not url.startswith(("http://", "https://")):
                raise HTTPException(400, f"URL {kind} invalide.")
            db.add(UserLink(user_id=user.id, kind=kind, url=url[:255]))
    db.commit()
    return {"ok": True}
