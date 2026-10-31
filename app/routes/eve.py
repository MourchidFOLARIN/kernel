"""Espace attaquant « Ève » (/eve). Actif seulement si DEMO_MODE=true, rôle « attaquant ».

Ève n'a besoin d'aucun privilège de base : elle exploite ce que le serveur lui donne
(flux des trames, clé broadcast diffusée en clair). L'interception se pilote par WS.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.content import load_json
from app.database import SessionLocal, get_db
from app.demo import get_settings, settings_payload
from app.deps import require_attacker
from app.models import Message, User
from app.security import csrf_token_for, get_session
from app.ws.hub import eve

router = APIRouter(tags=["eve"])
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))
from app import assets as _assets  # noqa: E402
_assets.install(templates)


@router.get("/eve", response_class=HTMLResponse)
def eve_home(request: Request, user: User = Depends(require_attacker)):
    if not config.DEMO_MODE:
        raise HTTPException(404, "Page introuvable.")
    db = SessionLocal()
    try:
        sess = get_session(db, request)
        settings = settings_payload(get_settings(db))
        return templates.TemplateResponse(request, "eve.html", {
            "request": request, "site": load_json("site"), "user": user,
            "csrf": csrf_token_for(request, sess), "domains": config.DOMAINS,
            "path": "/eve", "settings": settings, "intercept": eve.intercept,
            "seo": {"title": "Ève — Kernel", "description": ""},
        })
    finally:
        db.close()


@router.get("/api/eve/settings")
def eve_settings(db: DbSession = Depends(get_db), user: User = Depends(require_attacker)):
    """Réglages démo, clé broadcast comprise (faille volontaire)."""
    return settings_payload(get_settings(db))


@router.get("/api/eve/recent")
def eve_recent(limit: int = 50, db: DbSession = Depends(get_db),
               user: User = Depends(require_attacker)):
    """Derniers chiffrés vus par le serveur (tous confondus), pour alimenter les outils."""
    rows = db.scalars(select(Message).order_by(Message.id.desc()).limit(min(limit, 200))).all()
    return [{"id": m.id, "conversation_id": m.conversation_id, "sender_id": m.sender_id,
             "algo": m.algo, "mode": m.mode, "iv": m.iv_hex or "",
             "ciphertext": m.ciphertext_hex, "tag": m.tag_hex or "",
             "key_dist": m.key_dist, "key_fp": m.key_fp,
             "created_at": m.created_at.isoformat() + "Z"} for m in reversed(rows)]
