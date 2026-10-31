"""Dépendances FastAPI : utilisateur courant, contrôle des rôles, CSRF."""
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from app import config
from app.database import get_db
from app.models import Session, User
from app.security import get_session, verify_csrf


def current_session(request: Request, db: DbSession = Depends(get_db)) -> Session | None:
    return get_session(db, request)


def current_user(sess: Session | None = Depends(current_session)) -> User | None:
    return sess.user if sess else None


def require_user(user: User | None = Depends(current_user)) -> User:
    if not user:
        raise HTTPException(401, "Connexion requise.")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Accès réservé aux administrateurs.")
    return user


def require_attacker(user: User = Depends(require_user)) -> User:
    if not config.DEMO_MODE:
        raise HTTPException(404, "Page introuvable.")
    if user.role != "attaquant":
        raise HTTPException(403, "Accès refusé.")
    return user


async def csrf_protect(request: Request, sess: Session | None = Depends(current_session)) -> None:
    """À ajouter sur toute route POST/PUT/DELETE mutative."""
    token = request.headers.get("x-csrf-token")
    if not token and request.headers.get("content-type", "").startswith(
            ("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        token = form.get("csrf_token")
    verify_csrf(request, sess, token)
