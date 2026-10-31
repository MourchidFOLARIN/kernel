"""Version des fichiers statiques (anti-cache navigateur).

Les pages référencent /static/v-<hash>/… : après une mise à jour du code (et
redémarrage), toutes les URL changent, y compris celles des modules ES importés
en relatif. Le navigateur ne peut donc jamais mélanger ancien et nouveau JS.
"""
import hashlib

from app import config

_STATIC = config.BASE_DIR / "static"


def compute_version() -> str:
    h = hashlib.sha256()
    for p in sorted(_STATIC.rglob("*")):
        if p.is_file() and "uploads" not in p.relative_to(_STATIC).parts:
            h.update(str(p.relative_to(_STATIC)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()[:10]


ASSET_VERSION = compute_version()
STATIC_PREFIX = f"/static/v-{ASSET_VERSION}"


def install(templates) -> None:
    """Expose `static` (préfixe versionné) dans un environnement Jinja2Templates."""
    templates.env.globals["static"] = STATIC_PREFIX
    templates.env.globals["asset_version"] = ASSET_VERSION


class CacheControlMiddleware:
    """ASGI : réécrit /static/v-xxx/… → /static/… et pose les en-têtes de cache.

    - fichiers statiques : `no-cache` (revalidation ETag à chaque chargement) ;
    - pages HTML : `no-store`.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        is_static = path.startswith("/static/")
        if path.startswith("/static/v-"):
            parts = path.split("/", 3)  # ['', 'static', 'v-xxx', 'reste']
            new_path = "/static/" + (parts[3] if len(parts) > 3 else "")
            scope = dict(scope, path=new_path, raw_path=new_path.encode())

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control"]
                ctype = next((v for k, v in headers if k.lower() == b"content-type"), b"")
                if is_static:
                    headers.append((b"cache-control", b"no-cache"))
                elif ctype.startswith(b"text/html"):
                    headers.append((b"cache-control", b"no-store"))
                message = dict(message, headers=headers)
            await send(message)

        await self.app(scope, receive, send_wrapper)
