"""Sécurité : hachage argon2, sessions par cookie signé, CSRF, limitation des connexions."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request, Response
from starlette.requests import HTTPConnection
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.models import LoginAttempt, Session, User, now_utc

_ph = PasswordHasher()
_signer = URLSafeSerializer(config.SECRET_KEY, salt="kernel-session")
_csrf_signer = URLSafeSerializer(config.SECRET_KEY, salt="kernel-csrf")
CSRF_COOKIE = "kernel_csrf"


# ---------- Mots de passe ----------
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


# ---------- Sessions ----------
def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def create_session(db: DbSession, user: User, response: Response) -> Session:
    """Crée une session : jeton aléatoire, seul son haché est stocké en base."""
    token = secrets.token_urlsafe(32)
    sess = Session(user_id=user.id, token_hash=_sha256(token),
                   csrf_token=secrets.token_urlsafe(32),
                   expires_at=now_utc() + timedelta(days=config.SESSION_DAYS))
    db.add(sess)
    db.commit()
    response.set_cookie(config.SESSION_COOKIE, _signer.dumps(token), httponly=True,
                        samesite="lax", max_age=config.SESSION_DAYS * 86400, path="/")
    return sess


def get_session(db: DbSession, request: HTTPConnection) -> Session | None:
    raw = request.cookies.get(config.SESSION_COOKIE)
    if not raw:
        return None
    try:
        token = _signer.loads(raw)
    except BadSignature:
        return None
    sess = db.scalar(select(Session).where(Session.token_hash == _sha256(str(token))))
    if not sess or sess.expires_at < now_utc() or sess.user.is_suspended:
        return None
    return sess


def destroy_session(db: DbSession, request: HTTPConnection, response: Response) -> None:
    sess = get_session(db, request)
    if sess:
        db.delete(sess)
        db.commit()
    response.delete_cookie(config.SESSION_COOKIE, path="/")


# ---------- CSRF ----------
# Visiteur anonyme : « double soumission » — un cookie aléatoire HttpOnly + un jeton signé
# dérivé, injecté dans la page (<meta name="csrf-token">) et renvoyé en en-tête X-CSRF-Token.
# Membre connecté : jeton propre à la session (table sessions.csrf_token).
def ensure_csrf_cookie(request: Request, response: Response) -> str:
    value = request.cookies.get(CSRF_COOKIE) or getattr(request.state, "csrf_seed", None)
    if not value:
        value = secrets.token_urlsafe(24)
        response.set_cookie(CSRF_COOKIE, value, httponly=True, samesite="lax", path="/")
    request.state.csrf_seed = value
    return value


def csrf_token_for(request: Request, sess: Session | None, response: Response | None = None) -> str:
    if sess:
        return sess.csrf_token
    seed = request.cookies.get(CSRF_COOKIE) or getattr(request.state, "csrf_seed", None)
    if not seed and response is not None:
        seed = ensure_csrf_cookie(request, response)
    return _csrf_signer.dumps(seed or "")


def verify_csrf(request: Request, sess: Session | None, provided: str | None) -> None:
    if not provided:
        raise HTTPException(403, "Jeton CSRF manquant.")
    if sess and hmac.compare_digest(provided, sess.csrf_token):
        return
    seed = request.cookies.get(CSRF_COOKIE)
    try:
        if seed and hmac.compare_digest(str(_csrf_signer.loads(provided)), seed):
            return
    except BadSignature:
        pass
    raise HTTPException(403, "Jeton CSRF invalide.")


# ---------- Limitation des tentatives ----------
def client_ip(request: Request) -> str:
    # Volontairement pas de confiance dans X-Forwarded-For (proxy Burp possible).
    return request.client.host if request.client else "inconnu"


def is_rate_limited(db: DbSession, ip: str, username: str) -> bool:
    since = now_utc() - timedelta(seconds=config.LOGIN_WINDOW_SECONDS)
    db.execute(delete(LoginAttempt).where(LoginAttempt.attempted_at < since))
    count = db.scalar(select(func.count()).select_from(LoginAttempt).where(
        LoginAttempt.attempted_at >= since,
        (LoginAttempt.ip == ip) | (LoginAttempt.username == username.lower())))
    return (count or 0) >= config.LOGIN_MAX_ATTEMPTS


def record_failed_login(db: DbSession, ip: str, username: str) -> None:
    db.add(LoginAttempt(ip=ip, username=username.lower()))
    db.commit()


def clear_failed_logins(db: DbSession, ip: str, username: str) -> None:
    db.execute(delete(LoginAttempt).where(LoginAttempt.username == username.lower()))
    db.commit()


def gen_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def utc_in(minutes: int) -> datetime:
    return now_utc() + timedelta(minutes=minutes)
