"""Demandes de contact : envoyer, accepter, refuser, bloquer."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.orm import Session as DbSession

from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import Contact, User

router = APIRouter(prefix="/api/contacts", tags=["contacts"])


class ContactIn(BaseModel):
    user_id: int


def _other(c: Contact, me: int) -> int:
    return c.to_id if c.from_id == me else c.from_id


@router.get("")
def list_contacts(db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    rows = db.scalars(select(Contact).where(or_(Contact.from_id == user.id, Contact.to_id == user.id))).all()
    out = []
    for c in rows:
        oid = _other(c, user.id)
        o = db.get(User, oid)
        if not o:
            continue
        out.append({"id": c.id, "status": c.status, "from_me": c.from_id == user.id,
                    "user": {"id": o.id, "username": o.username,
                             "display_name": o.display_name or o.username, "domain": o.domain}})
    return out


@router.post("/request", dependencies=[Depends(csrf_protect)])
async def request_contact(data: ContactIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if data.user_id == user.id:
        raise HTTPException(400, "Impossible.")
    target = db.get(User, data.user_id)
    if not target or target.is_suspended:
        raise HTTPException(404, "Membre introuvable.")
    existing = db.scalar(select(Contact).where(
        ((Contact.from_id == user.id) & (Contact.to_id == data.user_id)) |
        ((Contact.from_id == data.user_id) & (Contact.to_id == user.id))))
    if existing:
        if existing.status == "blocked":
            raise HTTPException(403, "Contact bloqué.")
        return {"ok": True, "status": existing.status, "id": existing.id}
    c = Contact(from_id=user.id, to_id=data.user_id, status="pending")
    db.add(c)
    db.commit()
    from app.ws.hub import hub
    await hub.send_to_user(data.user_id, {"type": "contact.request", "from_id": user.id})
    return {"ok": True, "status": "pending", "id": c.id}


@router.post("/{cid}/accept", dependencies=[Depends(csrf_protect)])
async def accept(cid: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    c = db.get(Contact, cid)
    if not c or c.to_id != user.id or c.status != "pending":
        raise HTTPException(400, "Demande invalide.")
    c.status = "accepted"
    db.commit()
    from app.ws.hub import hub
    await hub.send_to_user(c.from_id, {"type": "contact.update", "id": c.id, "status": "accepted"})
    return {"ok": True}


@router.post("/{cid}/refuse", dependencies=[Depends(csrf_protect)])
def refuse(cid: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    c = db.get(Contact, cid)
    if not c or c.to_id != user.id or c.status != "pending":
        raise HTTPException(400, "Demande invalide.")
    db.delete(c)
    db.commit()
    return {"ok": True}


@router.post("/{user_id}/block", dependencies=[Depends(csrf_protect)])
def block(user_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if user_id == user.id:
        raise HTTPException(400, "Impossible.")
    existing = db.scalar(select(Contact).where(
        ((Contact.from_id == user.id) & (Contact.to_id == user_id)) |
        ((Contact.from_id == user_id) & (Contact.to_id == user.id))))
    if existing:
        existing.status = "blocked"
        existing.from_id, existing.to_id = user.id, user_id
    else:
        db.add(Contact(from_id=user.id, to_id=user_id, status="blocked"))
    db.commit()
    return {"ok": True}


@router.delete("/{cid}", dependencies=[Depends(csrf_protect)])
def remove(cid: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    c = db.get(Contact, cid)
    if not c or (c.from_id != user.id and c.to_id != user.id):
        raise HTTPException(404)
    db.delete(c)
    db.commit()
    return {"ok": True}
