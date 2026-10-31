"""Pages HTML (rendu serveur Jinja2, échappement automatique anti-XSS)."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app import config
from app.content import load_json, render_markdown
from app.database import get_db
from app.deps import current_session
from app.models import Conversation, ConversationMember, Event, Message, User, now_utc
from app.security import CSRF_COOKIE, csrf_token_for, ensure_csrf_cookie

router = APIRouter()
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))
from app import assets as _assets  # noqa: E402
_assets.install(templates)


def render(request: Request, template: str, sess=None, status_code: int = 200, **ctx) -> HTMLResponse:
    """Rendu commun : injecte site, utilisateur, jeton CSRF, SEO."""
    # Prépare la graine CSRF anonyme avant de calculer le jeton.
    seed = request.cookies.get(CSRF_COOKIE) or getattr(request.state, "csrf_seed", None)
    need_cookie = False
    if not sess and not seed:
        seed = ensure_csrf_cookie(request, HTMLResponse())  # écrit request.state.csrf_seed
        need_cookie = True

    ctx.update(request=request, site=load_json("site"), user=sess.user if sess else None,
               csrf=csrf_token_for(request, sess), domains=config.DOMAINS, path=request.url.path,
               demo_mode=config.DEMO_MODE)
    resp = templates.TemplateResponse(request, template, ctx, status_code=status_code)
    if need_cookie:
        resp.set_cookie(CSRF_COOKIE, request.state.csrf_seed, httponly=True, samesite="lax", path="/")
    return resp


def site_stats(db: DbSession) -> dict:
    """Statistiques RÉELLES lues en base (jamais de chiffres inventés)."""
    return {
        "members": db.scalar(select(func.count()).select_from(User).where(User.role == "membre")) or 0,
        "rooms": db.scalar(select(func.count()).select_from(Conversation).where(Conversation.kind == "room")) or 0,
        "messages": db.scalar(select(func.count()).select_from(Message).where(Message.deleted_at.is_(None))) or 0,
    }


def rooms_with_counts(db: DbSession, domain: str | None = None):
    q = (select(Conversation, func.count(ConversationMember.id))
         .outerjoin(ConversationMember, ConversationMember.conversation_id == Conversation.id)
         .where(Conversation.kind == "room").group_by(Conversation.id).order_by(Conversation.id))
    if domain:
        q = q.where(Conversation.domain == domain)
    return [{"room": r, "members": n} for r, n in db.execute(q).all()]


@router.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def home(request: Request, db: DbSession = Depends(get_db), sess=Depends(current_session)):
    return render(request, "home.html", sess, c=load_json("home"), stats=site_stats(db))


@router.get("/fonctionnalites", response_class=HTMLResponse)
def features(request: Request, sess=Depends(current_session)):
    return render(request, "features.html", sess, c=load_json("features"))


@router.get("/communautes", response_class=HTMLResponse)
def communities(request: Request, domaine: str | None = None, db: DbSession = Depends(get_db),
                sess=Depends(current_session)):
    domain = domaine if domaine in config.DOMAINS else None
    used = [d for (d,) in db.execute(select(Conversation.domain).where(
        Conversation.kind == "room").distinct()).all() if d]
    return render(request, "communities.html", sess, c=load_json("communities"),
                  rooms=rooms_with_counts(db, domain), active=domain,
                  filters=[d for d in config.DOMAINS if d in used])


def _landing(key: str):
    def view(request: Request, db: DbSession = Depends(get_db), sess=Depends(current_session)):
        c = load_json("landings")[key]
        rooms = [r for r in rooms_with_counts(db) if r["room"].slug in c["rooms"]]
        return render(request, "landing.html", sess, c=c, rooms=rooms)
    return view


for _key in ("dev", "cybersecurite", "data-ia"):
    router.add_api_route(f"/{_key}", _landing(_key), methods=["GET"], response_class=HTMLResponse)


@router.get("/evenements", response_class=HTMLResponse)
def events(request: Request, db: DbSession = Depends(get_db), sess=Depends(current_session)):
    upcoming = db.scalars(select(Event).where(Event.starts_at >= now_utc()).order_by(Event.starts_at)).all()
    return render(request, "events.html", sess, c=load_json("events"), events=upcoming)


@router.get("/a-propos", response_class=HTMLResponse)
def about(request: Request, sess=Depends(current_session)):
    return render(request, "about.html", sess, c=load_json("team"))


@router.get("/faq", response_class=HTMLResponse)
def faq(request: Request, sess=Depends(current_session)):
    return render(request, "faq.html", sess, c=load_json("faq"))


@router.get("/contact", response_class=HTMLResponse)
def contact(request: Request, sess=Depends(current_session)):
    return render(request, "contact.html", sess, c=load_json("contact"))


@router.get("/regles", response_class=HTMLResponse)
def rules(request: Request, sess=Depends(current_session)):
    return render(request, "prose.html", sess, body=render_markdown("rules"), extra=render_markdown("legal"),
                  seo={"title": "Règles & CGU — Kernel", "description": "Règles de la communauté Kernel et conditions d'utilisation."})


@router.get("/confidentialite", response_class=HTMLResponse)
def privacy(request: Request, sess=Depends(current_session)):
    return render(request, "prose.html", sess, body=render_markdown("privacy"),
                  seo={"title": "Confidentialité — Kernel", "description": "Quelles données Kernel collecte et pourquoi."})


@router.get("/rejoindre", response_class=HTMLResponse)
def join(request: Request, domaine: str | None = None, sess=Depends(current_session)):
    if sess:
        return RedirectResponse("/app", 303)
    return render(request, "join.html", sess, c=load_json("auth")["join"],
                  preselect=domaine if domaine in config.DOMAINS else "")


@router.get("/connexion", response_class=HTMLResponse)
def login(request: Request, sess=Depends(current_session)):
    if sess:
        return RedirectResponse("/app", 303)
    return render(request, "login.html", sess, c=load_json("auth")["login"])


@router.get("/mot-de-passe-oublie", response_class=HTMLResponse)
def forgot(request: Request, sess=Depends(current_session)):
    return render(request, "forgot.html", sess, c=load_json("auth")["forgot"])


@router.get("/app", response_class=HTMLResponse)
def member_home(request: Request, db: DbSession = Depends(get_db), sess=Depends(current_session)):
    """Espace membre (étape 1 : profil ; la messagerie arrive à l'étape 2)."""
    if not sess:
        return RedirectResponse("/connexion", 303)
    return render(request, "app.html", sess, rooms=rooms_with_counts(db),
                  seo={"title": "Mon espace — Kernel", "description": ""})


@router.get("/404", response_class=HTMLResponse)
def page_404(request: Request, sess=Depends(current_session)):
    return render(request, "error.html", sess, status_code=404, code=404,
                  message="Cette page n'existe pas (ou plus).")


@router.get("/500", response_class=HTMLResponse)
def page_500(request: Request, sess=Depends(current_session)):
    return render(request, "error.html", sess, status_code=500, code=500,
                  message="Quelque chose s'est mal passé de notre côté.")
