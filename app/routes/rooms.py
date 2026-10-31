"""Salons thématiques : liste publique, rejoindre / quitter (membres)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.chat import is_member
from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import ActivityLog, Conversation, ConversationMember, User, now_utc

router = APIRouter(prefix="/api/rooms", tags=["rooms"])


@router.get("")
def list_rooms(domaine: str | None = None, db: DbSession = Depends(get_db)):
    q = (select(Conversation, func.count(ConversationMember.id))
         .outerjoin(ConversationMember, ConversationMember.conversation_id == Conversation.id)
         .where(Conversation.kind == "room").group_by(Conversation.id).order_by(Conversation.id))
    if domaine:
        q = q.where(Conversation.domain == domaine)
    return [{"id": r.id, "title": r.title, "slug": r.slug, "domain": r.domain,
             "description": r.description, "members": n}
            for r, n in db.execute(q).all()]


@router.post("/{room_id}/join", dependencies=[Depends(csrf_protect)])
async def join_room(room_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    room = db.get(Conversation, room_id)
    if not room or room.kind != "room":
        raise HTTPException(404, "Salon introuvable.")
    if not is_member(db, room_id, user.id):
        db.add(ConversationMember(conversation_id=room_id, user_id=user.id, joined_at=now_utc(),
                                      last_read_at=now_utc()))
        db.add(ActivityLog(actor_id=user.id, action="salon.rejoindre",
                           detail_json=f'{{"id":{room_id}}}'))
        db.commit()
        from app.chat import member_ids
        from app.ws.hub import hub
        await hub.send_to_users(set(member_ids(db, room_id)) - {user.id},
                                {"type": "conv.member", "conversation_id": room_id, "user_id": user.id})
    return {"ok": True, "id": room_id}


@router.post("/{room_id}/leave", dependencies=[Depends(csrf_protect)])
def leave_room(room_id: int, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    mem = db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == room_id, ConversationMember.user_id == user.id))
    if not mem:
        raise HTTPException(400, "Vous n'êtes pas membre de ce salon.")
    room = db.get(Conversation, room_id)
    if not room or room.kind != "room":
        raise HTTPException(404, "Salon introuvable.")
    db.delete(mem)
    db.commit()
    return {"ok": True}
