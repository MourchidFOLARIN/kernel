"""Inscription, connexion, déconnexion, réinitialisation de mot de passe."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.chat import ensure_default_rooms
from app.database import get_db
from app.deps import csrf_protect, current_session
from app.models import ActivityLog, PasswordResetCode, User
from app.schemas import ForgotIn, LoginIn, RegisterIn, ResetIn
from app.security import (clear_failed_logins, client_ip, create_session, destroy_session,
                          gen_code, hash_password, is_rate_limited, record_failed_login,
                          utc_in, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", dependencies=[Depends(csrf_protect)])
def register(data: RegisterIn, request: Request, response: Response,
             db: DbSession = Depends(get_db)):
    if db.scalar(select(User).where(User.username == data.username.lower())):
        raise HTTPException(400, "Ce pseudo est déjà pris.")
    if db.scalar(select(User).where(User.email == data.email.lower())):
        raise HTTPException(400, "Cet e-mail est déjà utilisé.")
    user = User(username=data.username.lower(), email=str(data.email).lower(),
                password_hash=hash_password(data.password),
                display_name=data.username, domain=data.domain,
                email_verified=True)  # pas d'envoi d'e-mail en étape 1
    db.add(user)
    db.flush()
    db.add(ActivityLog(actor_id=user.id, action="inscription",
                       detail_json=f'{{"username":"{user.username}"}}'))
    ensure_default_rooms(db, user)
    db.commit()
    create_session(db, user, response)
    return {"ok": True, "username": user.username, "redirect": "/app"}


@router.post("/login", dependencies=[Depends(csrf_protect)])
def login(data: LoginIn, request: Request, response: Response,
          db: DbSession = Depends(get_db)):
    ip = client_ip(request)
    if is_rate_limited(db, ip, data.username):
        raise HTTPException(429, "Trop de tentatives. Réessayez dans quelques minutes.")
    user = db.scalar(select(User).where(or_(
        User.username == data.username.lower(),
        User.email == data.username.lower())))
    if not user or not verify_password(user.password_hash, data.password):
        record_failed_login(db, ip, data.username)
        raise HTTPException(401, "Identifiants incorrects.")
    if user.is_suspended:
        raise HTTPException(403, "Ce compte est suspendu.")
    clear_failed_logins(db, ip, data.username)
    create_session(db, user, response)
    db.add(ActivityLog(actor_id=user.id, action="connexion", detail_json="{}"))
    db.commit()
    return {"ok": True, "username": user.username, "role": user.role, "redirect": "/app"}


@router.post("/logout", dependencies=[Depends(csrf_protect)])
def logout(request: Request, response: Response, db: DbSession = Depends(get_db),
           sess=Depends(current_session)):
    destroy_session(db, request, response)
    return {"ok": True, "redirect": "/"}


@router.post("/forgot", dependencies=[Depends(csrf_protect)])
def forgot(data: ForgotIn, db: DbSession = Depends(get_db)):
    """Génère un code affiché à l'écran (pas d'e-mail). Réponse neutre si inconnu."""
    user = db.scalar(select(User).where(or_(
        User.username == data.username.lower(),
        User.email == data.username.lower())))
    if not user:
        return {"ok": True, "found": False,
                "message": "Si ce compte existe, un code a été généré."}
    code = gen_code()
    db.add(PasswordResetCode(user_id=user.id, code=code,
                             expires_at=utc_in(config.RESET_CODE_MINUTES)))
    db.commit()
    return {"ok": True, "found": True, "code": code,
            "expires_minutes": config.RESET_CODE_MINUTES,
            "message": f"Code valable {config.RESET_CODE_MINUTES} minutes."}


@router.post("/reset", dependencies=[Depends(csrf_protect)])
def reset(data: ResetIn, db: DbSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == data.username.lower()))
    if not user:
        raise HTTPException(400, "Code ou compte invalide.")
    row = db.scalar(select(PasswordResetCode)
                    .where(PasswordResetCode.user_id == user.id,
                           PasswordResetCode.code == data.code)
                    .order_by(PasswordResetCode.id.desc()))
    from app.models import now_utc
    if not row or row.expires_at < now_utc():
        raise HTTPException(400, "Code invalide ou expiré.")
    user.password_hash = hash_password(data.password)
    db.delete(row)
    db.add(ActivityLog(actor_id=user.id, action="reset_mdp", detail_json="{}"))
    db.commit()
    return {"ok": True, "message": "Mot de passe mis à jour. Vous pouvez vous connecter."}


@router.get("/me")
def me(sess=Depends(current_session)):
    if not sess:
        return {"authenticated": False}
    u = sess.user
    return {"authenticated": True, "id": u.id, "username": u.username,
            "display_name": u.display_name, "role": u.role, "domain": u.domain}
