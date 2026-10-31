"""Signalements de messages / membres."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from app.database import get_db
from app.deps import csrf_protect, require_user
from app.models import Message, Report, User

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportIn(BaseModel):
    target_type: str  # message|user
    target_id: int
    reason: str = Field(min_length=3, max_length=1000)


@router.post("", dependencies=[Depends(csrf_protect)])
def create_report(data: ReportIn, db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    if data.target_type not in ("message", "user"):
        raise HTTPException(400, "Type invalide.")
    if data.target_type == "message" and not db.get(Message, data.target_id):
        raise HTTPException(404, "Message introuvable.")
    if data.target_type == "user" and not db.get(User, data.target_id):
        raise HTTPException(404, "Membre introuvable.")
    r = Report(reporter_id=user.id, target_type=data.target_type, target_id=data.target_id,
               reason=data.reason.strip())
    db.add(r)
    db.commit()
    return {"ok": True, "id": r.id}
