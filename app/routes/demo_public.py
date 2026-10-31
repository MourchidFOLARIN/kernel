"""Réglages de démo visibles des clients connectés (clé broadcast volontairement exposée)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from app.database import get_db
from app.demo import get_settings, settings_payload
from app.deps import require_user
from app.models import User

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.get("/settings")
def public_settings(db: DbSession = Depends(get_db), user: User = Depends(require_user)):
    return settings_payload(get_settings(db))
