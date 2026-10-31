"""Profil et annuaire (stubs utiles dès l'étape 1)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import User
from app.schemas import ProfileUpdate
from app.ws.hub import hub

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/me")
def my_profile(user: User = Depends(require_user)):
    return {"id": user.id, "username": user.username, "display_name": user.display_name,
            "bio": user.bio, "domain": user.domain, "role": user.role,
            "skills": [s.tag for s in user.skills],
            "links": [{"kind": l.kind, "url": l.url} for l in user.links]}


@router.patch("/me", dependencies=[Depends(csrf_protect)])
def update_me(data: ProfileUpdate, db: DbSession = Depends(get_db),
              user: User = Depends(require_user)):
    from app.config import DOMAINS
    if data.domain not in DOMAINS:
        raise HTTPException(400, "Domaine inconnu.")
    user.display_name = data.display_name.strip() or user.username
    user.bio = data.bio.strip()
    user.domain = data.domain
    db.commit()
    return {"ok": True}


@router.get("/directory")
def directory(q: str = "", domaine: str = "", skill: str = "",
              db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    from datetime import timedelta
    from app.models import Message, UserSkill, now_utc
    from sqlalchemy import func
    # Annuaire : tous les membres actifs sauf soi-même (rôle attaquant masqué).
    stmt = select(User).where(User.is_suspended.is_(False), User.role != "attaquant",
                              User.id != user.id)
    if domaine:
        stmt = stmt.where(User.domain == domaine)
    if skill:
        stmt = stmt.join(UserSkill).where(UserSkill.tag == skill.lower())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where((User.username.ilike(like)) | (User.display_name.ilike(like)))
    rows = db.scalars(stmt.order_by(User.username).limit(500)).all()
    week = now_utc() - timedelta(days=7)
    out = []
    for u in rows:
        n_msg = db.scalar(select(func.count()).select_from(Message).where(
            Message.sender_id == u.id, Message.deleted_at.is_(None))) or 0
        badges = []
        if u.created_at and u.created_at >= week:
            badges.append("Nouveau")
        if n_msg >= 5:
            badges.append("Contributeur")
        out.append({"id": u.id, "username": u.username, "display_name": u.display_name,
                    "domain": u.domain, "bio": (u.bio or "")[:120],
                    "avatar": u.avatar_path, "skills": [s.tag for s in u.skills],
                    "links": [{"kind": l.kind, "url": l.url} for l in u.links],
                    "online": u.id in hub.online_ids(), "badges": badges})
    return out


@router.get("/all")
def all_members(db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    """Tous les membres inscrits et non suspendus (sauf soi-meme), pour le
    selecteur Nouveau message. Le filtrage est instantane, cote client."""
    online = hub.online_ids()
    rows = db.scalars(select(User).where(User.is_suspended.is_(False), User.id != user.id)
                      .order_by(User.username)).all()
    return [{"id": u.id, "username": u.username, "display_name": u.display_name or u.username,
             "domain": u.domain or "", "avatar": u.avatar_path, "online": u.id in online}
            for u in rows]


@router.get("/{username}")
def public_profile(username: str, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    u = db.scalar(select(User).where(User.username == username.lower()))
    if not u or u.is_suspended or u.role == "attaquant":
        raise HTTPException(404, "Profil introuvable.")
    return {"id": u.id, "username": u.username, "display_name": u.display_name,
            "bio": u.bio, "domain": u.domain, "avatar": u.avatar_path,
            "skills": [s.tag for s in u.skills],
            "links": [{"kind": l.kind, "url": l.url} for l in u.links]}
