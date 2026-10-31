"""Espace administrateur : dashboard, membres, salons, événements, contact, signalements, démo."""
import json
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.content import load_json
from app.database import SessionLocal, get_db
from app.demo import (ALGO_TO_MODE, ALLOWED_ALGOS, KEY_DISTRIBUTIONS, PRESENTATION,
                      get_settings, new_broadcast_key, new_des_short_key,
                      settings_payload, update_settings)
from app.deps import csrf_protect, require_admin
from app.models import (ActivityLog, ContactMessage, Conversation, ConversationMember,
                        Event, Message, PasswordResetCode, Report, User, now_utc)
from app.security import csrf_token_for, get_session, hash_password, utc_in
from app.ws.hub import hub

router = APIRouter(tags=["admin"])
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))
from app import assets as _assets  # noqa: E402
_assets.install(templates)


def _render_admin(request: Request, user: User, template: str, **ctx):
    db = SessionLocal()
    try:
        sess = get_session(db, request)
        return templates.TemplateResponse(request, template, {
            "request": request, "site": load_json("site"), "user": user,
            "csrf": csrf_token_for(request, sess), "domains": config.DOMAINS,
            "path": "/admin", "demo_mode": config.DEMO_MODE,
            "seo": {"title": "Administration — Kernel", "description": ""},
            **ctx,
        })
    finally:
        db.close()


@router.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, user: User = Depends(require_admin),
               db: DbSession = Depends(get_db)):
    online = len(hub.online_ids())
    n_msg = db.scalar(select(func.count()).select_from(Message)) or 0
    by_algo = dict(db.execute(
        select(Message.algo, func.count()).group_by(Message.algo)).all())
    n_users = db.scalar(select(func.count()).select_from(User)) or 0
    n_contact = db.scalar(select(func.count()).select_from(ContactMessage)
                          .where(ContactMessage.is_read.is_(False))) or 0
    n_reports = db.scalar(select(func.count()).select_from(Report)
                          .where(Report.status == "ouvert")) or 0
    settings = settings_payload(get_settings(db))
    return _render_admin(request, user, "admin.html",
                         stats={"online": online, "messages": n_msg, "users": n_users,
                                "by_algo": by_algo, "contact_unread": n_contact,
                                "reports_open": n_reports},
                         settings=settings, presentation=PRESENTATION,
                         algos=sorted(ALLOWED_ALGOS), distributions=KEY_DISTRIBUTIONS)


# ---------- API démo ----------
class DemoUpdate(BaseModel):
    algo: str | None = None
    key_distribution: str | None = None
    presentation_step: int | None = None


@router.get("/api/admin/demo")
def api_demo_get(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    return settings_payload(get_settings(db))


@router.put("/api/admin/demo", dependencies=[Depends(csrf_protect)])
async def api_demo_put(data: DemoUpdate, db: DbSession = Depends(get_db),
                       user: User = Depends(require_admin)):
    try:
        row = update_settings(db, algo=data.algo, key_distribution=data.key_distribution,
                              presentation_step=data.presentation_step, actor_id=user.id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    payload = settings_payload(row)
    await hub.broadcast(payload)
    return payload


@router.post("/api/admin/demo/new-key", dependencies=[Depends(csrf_protect)])
async def api_demo_new_key(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    row = new_broadcast_key(db, actor_id=user.id)
    payload = settings_payload(row)
    await hub.broadcast(payload)
    return payload


@router.post("/api/admin/demo/des-short-key", dependencies=[Depends(csrf_protect)])
async def api_demo_des_short(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    """Active DES-CBC avec une clé à 24 bits efficaces (pour la démo de force brute)."""
    if not config.DEMO_MODE:
        raise HTTPException(404, "Indisponible hors DEMO_MODE.")
    row = new_des_short_key(db, actor_id=user.id)
    payload = settings_payload(row)
    await hub.broadcast(payload)
    return payload


@router.post("/api/admin/demo/presentation/next", dependencies=[Depends(csrf_protect)])
async def api_demo_pres_next(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    row = get_settings(db)
    nxt = min(row.presentation_step + 1, len(PRESENTATION) - 1)
    row = update_settings(db, presentation_step=nxt, actor_id=user.id)
    payload = settings_payload(row)
    await hub.broadcast(payload)
    return {**payload, "label": PRESENTATION[nxt]["label"],
            "note": PRESENTATION[nxt].get("note")}


@router.post("/api/admin/demo/presentation/reset", dependencies=[Depends(csrf_protect)])
async def api_demo_pres_reset(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    row = update_settings(db, presentation_step=0, actor_id=user.id)
    payload = settings_payload(row)
    await hub.broadcast(payload)
    return payload


# ---------- Membres ----------
@router.get("/api/admin/users")
def api_users(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(User).order_by(User.id)).all()
    online = hub.online_ids()
    return [{"id": u.id, "username": u.username, "email": u.email, "role": u.role,
             "domain": u.domain, "is_suspended": u.is_suspended,
             "online": u.id in online, "created_at": u.created_at.isoformat() + "Z"}
            for u in rows]


@router.post("/api/admin/users/{uid}/suspend", dependencies=[Depends(csrf_protect)])
def suspend_user(uid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    target = db.get(User, uid)
    if not target or target.role == "admin":
        raise HTTPException(400, "Impossible.")
    target.is_suspended = not target.is_suspended
    db.add(ActivityLog(actor_id=user.id, action="membre.suspendre",
                       detail_json=json.dumps({"id": uid, "suspended": target.is_suspended})))
    db.commit()
    return {"ok": True, "is_suspended": target.is_suspended}


@router.delete("/api/admin/users/{uid}", dependencies=[Depends(csrf_protect)])
def delete_user(uid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    target = db.get(User, uid)
    if not target or target.role == "admin" or target.id == user.id:
        raise HTTPException(400, "Impossible de supprimer ce compte.")
    db.delete(target)
    db.add(ActivityLog(actor_id=user.id, action="membre.supprimer",
                       detail_json=json.dumps({"id": uid})))
    db.commit()
    return {"ok": True}


@router.post("/api/admin/users/{uid}/reset-password", dependencies=[Depends(csrf_protect)])
def reset_password(uid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    target = db.get(User, uid)
    if not target:
        raise HTTPException(404, "Introuvable.")
    code = f"{secrets.randbelow(10**6):06d}"
    # Mot de passe temporaire = Temp + code
    temp = f"Temp{code}!"
    target.password_hash = hash_password(temp)
    db.add(PasswordResetCode(user_id=target.id, code=code, expires_at=utc_in(60)))
    db.add(ActivityLog(actor_id=user.id, action="membre.reset_mdp",
                       detail_json=json.dumps({"id": uid})))
    db.commit()
    return {"ok": True, "temporary_password": temp, "code": code}


# ---------- Salons (basique) ----------
class RoomIn(BaseModel):
    title: str = Field(min_length=1, max_length=80)
    slug: str = Field(min_length=1, max_length=80)
    domain: str = "autre"
    description: str = ""


@router.get("/api/admin/rooms")
def admin_rooms(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(Conversation).where(Conversation.kind == "room").order_by(Conversation.id)).all()
    return [{"id": r.id, "title": r.title, "slug": r.slug, "domain": r.domain,
             "description": r.description} for r in rows]


@router.post("/api/admin/rooms", dependencies=[Depends(csrf_protect)])
def create_room(data: RoomIn, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    if db.scalar(select(Conversation).where(Conversation.slug == data.slug)):
        raise HTTPException(400, "Slug déjà pris.")
    room = Conversation(kind="room", title=data.title if data.title.startswith("#") else f"#{data.title}",
                        slug=data.slug, domain=data.domain, description=data.description,
                        created_by=user.id)
    db.add(room)
    db.commit()
    return {"id": room.id}


@router.delete("/api/admin/rooms/{rid}", dependencies=[Depends(csrf_protect)])
def delete_room(rid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    room = db.get(Conversation, rid)
    if not room or room.kind != "room":
        raise HTTPException(404)
    db.delete(room)
    db.commit()
    return {"ok": True}


# ---------- Événements ----------
class EventIn(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    description: str = ""
    kind: str = "rencontre"
    starts_at: str  # ISO
    ends_at: str | None = None


@router.get("/api/admin/events")
def admin_events(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(Event).order_by(Event.starts_at.desc())).all()
    return [{"id": e.id, "title": e.title, "description": e.description, "kind": e.kind,
             "starts_at": e.starts_at.isoformat() + "Z",
             "ends_at": e.ends_at.isoformat() + "Z" if e.ends_at else None} for e in rows]


@router.post("/api/admin/events", dependencies=[Depends(csrf_protect)])
def create_event(data: EventIn, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    starts = datetime.fromisoformat(data.starts_at.replace("Z", ""))
    ends = datetime.fromisoformat(data.ends_at.replace("Z", "")) if data.ends_at else None
    e = Event(title=data.title, description=data.description, kind=data.kind,
              starts_at=starts, ends_at=ends, created_by=user.id)
    db.add(e)
    db.commit()
    return {"id": e.id}


@router.delete("/api/admin/events/{eid}", dependencies=[Depends(csrf_protect)])
def delete_event(eid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    e = db.get(Event, eid)
    if not e:
        raise HTTPException(404)
    db.delete(e)
    db.commit()
    return {"ok": True}


# ---------- Contact / signalements / journal ----------
@router.get("/api/admin/contact")
def admin_contact(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(ContactMessage).order_by(ContactMessage.id.desc()).limit(100)).all()
    return [{"id": m.id, "name": m.name, "email": m.email, "subject": m.subject,
             "body": m.body, "is_read": m.is_read,
             "created_at": m.created_at.isoformat() + "Z"} for m in rows]


@router.post("/api/admin/contact/{mid}/read", dependencies=[Depends(csrf_protect)])
def mark_contact(mid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    m = db.get(ContactMessage, mid)
    if m:
        m.is_read = True
        db.commit()
    return {"ok": True}


@router.get("/api/admin/reports")
def admin_reports(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(Report).order_by(Report.id.desc()).limit(100)).all()
    return [{"id": r.id, "reporter_id": r.reporter_id, "target_type": r.target_type,
             "target_id": r.target_id, "reason": r.reason, "status": r.status,
             "created_at": r.created_at.isoformat() + "Z"} for r in rows]


@router.post("/api/admin/reports/{rid}/close", dependencies=[Depends(csrf_protect)])
def close_report(rid: int, db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    r = db.get(Report, rid)
    if not r:
        raise HTTPException(404)
    r.status = "clos"
    db.commit()
    return {"ok": True}


@router.get("/api/admin/activity")
def admin_activity(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.scalars(select(ActivityLog).order_by(ActivityLog.id.desc()).limit(100)).all()
    return [{"id": a.id, "actor_id": a.actor_id, "action": a.action,
             "detail_json": a.detail_json,
             "created_at": a.created_at.isoformat() + "Z"} for a in rows]


@router.get("/api/admin/dashboard")
def dashboard(db: DbSession = Depends(get_db), user: User = Depends(require_admin)):
    by_algo = dict(db.execute(select(Message.algo, func.count()).group_by(Message.algo)).all())
    return {"online": len(hub.online_ids()),
            "messages": db.scalar(select(func.count()).select_from(Message)) or 0,
            "users": db.scalar(select(func.count()).select_from(User)) or 0,
            "by_algo": by_algo}
