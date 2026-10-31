"""Formulaire de contact (avec honeypot anti-spam)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from app.database import get_db
from app.deps import csrf_protect
from app.models import ContactMessage
from app.schemas import ContactIn

router = APIRouter(prefix="/api", tags=["contact"])


@router.post("/contact", dependencies=[Depends(csrf_protect)])
def send_contact(data: ContactIn, db: DbSession = Depends(get_db)):
    # Honeypot : un bot remplit le champ caché « website » → on fait semblant d'accepter.
    if data.website.strip():
        return {"ok": True}
    db.add(ContactMessage(name=data.name.strip(), email=str(data.email).lower(),
                          subject=data.subject.strip(), body=data.body.strip()))
    db.commit()
    return {"ok": True}
