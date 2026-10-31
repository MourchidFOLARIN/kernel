"""Groupes privés : création, ajout / retrait de membres."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.chat import is_member, member_ids
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import Conversation, ConversationMember, User, now_utc
from app.ws.hub import hub

router = APIRouter(prefix="/api/groups", tags=["groups"])


class GroupIn(BaseModel):
    title: str = Field(min_length=1, max_length=80)
    member_ids: list[int] = []


class MemberIn(BaseModel):
    user_id: int


@router.post("", dependencies=[Depends(csrf_protect)])
async def create_group(data: GroupIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    conv = Conversation(kind="group", title=data.title.strip(), created_by=user.id)
    db.add(conv)
    db.flush()
    ids = {user.id, *[i for i in data.member_ids if i != user.id]}
    for uid in ids:
        if db.get(User, uid):
            db.add(ConversationMember(conversation_id=conv.id, user_id=uid, joined_at=now_utc()))
    db.commit()
    await hub.send_to_users(list(ids), {"type": "conv.created", "id": conv.id, "kind": "group",
                                        "title": conv.title})
    return {"id": conv.id, "kind": "group", "title": conv.title}


@router.post("/{gid}/members", dependencies=[Depends(csrf_protect)])
async def add_member(gid: int, data: MemberIn, db: DbSession = Depends(get_db),
                     user: User = Depends(require_user)):
    conv = db.get(Conversation, gid)
    if not conv or conv.kind != "group":
        raise HTTPException(404)
    if not is_member(db, gid, user.id):
        raise HTTPException(403, "Vous n'êtes pas membre.")
    if not db.get(User, data.user_id):
        raise HTTPException(404, "Membre introuvable.")
    if not is_member(db, gid, data.user_id):
        db.add(ConversationMember(conversation_id=gid, user_id=data.user_id, joined_at=now_utc()))
        db.commit()
        await hub.send_to_users(member_ids(db, gid) + [data.user_id],
                                {"type": "conv.member", "conversation_id": gid,
                                 "user_id": data.user_id, "added": True})
    return {"ok": True}


@router.delete("/{gid}/members/{uid}", dependencies=[Depends(csrf_protect)])
async def remove_member(gid: int, uid: int, db: DbSession = Depends(get_db),
                        user: User = Depends(require_user)):
    conv = db.get(Conversation, gid)
    if not conv or conv.kind != "group":
        raise HTTPException(404)
    # Créateur ou soi-même
    if user.id != conv.created_by and user.id != uid:
        raise HTTPException(403, "Seul le créateur peut retirer un membre.")
    mem = db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == gid, ConversationMember.user_id == uid))
    if not mem:
        raise HTTPException(400, "Pas membre.")
    if uid == conv.created_by:
        raise HTTPException(400, "Le créateur ne peut pas quitter (supprimez le groupe).")
    db.delete(mem)
    db.commit()
    await hub.send_to_users(member_ids(db, gid) + [uid],
                            {"type": "conv.member", "conversation_id": gid,
                             "user_id": uid, "added": False})
    return {"ok": True}
