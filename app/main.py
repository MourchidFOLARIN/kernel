"""Application FastAPI Kernel."""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import config
from app.routes import (account, admin, auth, contact, contacts, demo_public, eve, group_keys,
                       groups, keys, messages, pages, reports, rooms, users)
from app.ws import handlers as ws_handlers

app = FastAPI(title=config.APP_NAME, docs_url=None, redoc_url=None)
from app.assets import CacheControlMiddleware  # noqa: E402
app.add_middleware(CacheControlMiddleware)
app.mount("/static", StaticFiles(directory=str(config.BASE_DIR / "static")), name="static")

app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(messages.router)
app.include_router(rooms.router)
app.include_router(admin.router)
app.include_router(demo_public.router)
app.include_router(keys.router)
app.include_router(group_keys.router)
app.include_router(account.router)
app.include_router(reports.router)
app.include_router(groups.router)
app.include_router(contacts.router)
app.include_router(eve.router)
app.include_router(contact.router)
app.include_router(ws_handlers.router)


@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    wants_html = "text/html" in request.headers.get("accept", "")
    if wants_html and exc.status_code in (404, 403, 401, 500):
        from app.deps import current_session
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            sess = current_session(request, db)
            code = 404 if exc.status_code in (401, 403, 404) else 500
            msg = {401: "Connexion requise.", 403: "Accès refusé.",
                   404: "Cette page n'existe pas (ou plus).",
                   500: "Erreur serveur."}.get(exc.status_code, str(exc.detail))
            return pages.render(request, "error.html", sess, status_code=code,
                                code=code, message=msg)
        finally:
            db.close()
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_exc(request: Request, exc: RequestValidationError):
    errs = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", []) if x != "body")
        errs.append(f"{loc}: {e.get('msg')}" if loc else e.get("msg"))
    return JSONResponse({"detail": "; ".join(errs)}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    if "text/html" in request.headers.get("accept", ""):
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            from app.security import get_session
            sess = get_session(db, request)
            return pages.render(request, "error.html", sess, status_code=500,
                                code=500, message="Quelque chose s'est mal passé de notre côté.")
        finally:
            db.close()
    return JSONResponse({"detail": "Erreur interne."}, status_code=500)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi.responses import FileResponse
    return FileResponse(config.BASE_DIR / "static" / "favicon.svg", media_type="image/svg+xml")
