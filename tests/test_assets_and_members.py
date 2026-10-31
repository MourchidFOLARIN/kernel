"""Cache des assets (versionnés + no-cache) et annuaire complet pour « Nouveau message »."""
from app import assets
from tests.test_multiuser import _new_client, _register


def test_static_versioned_path_and_cache_headers(client):
    r = client.get(f"{assets.STATIC_PREFIX}/js/app.js")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-cache"
    assert client.get("/static/js/app.js").headers["cache-control"] == "no-cache"
    assert "no-store" in client.get("/connexion").headers["cache-control"]


def test_app_page_uses_versioned_assets():
    c = _new_client()
    _register(c, "vera")
    html = c.get("/app").text
    assert f'{assets.STATIC_PREFIX}/js/app.js' in html
    import re
    assert not re.search(r'(src|href)="/static/(?!v-|uploads/)', html)


def test_users_all_lists_everyone_but_me():
    a, b = _new_client(), _new_client()
    _register(a, "lina")
    _register(b, "marc")
    users = a.get("/api/users/all").json()
    names = {u["username"] for u in users}
    assert "marc" in names and "alice" in names and "lina" not in names
    assert {"id", "username", "display_name", "domain", "online"} <= set(users[0])


def test_public_key_absent_is_not_404():
    a = _new_client()
    _register(a, "nora")
    me = [u for u in a.get("/api/users/all").json() if u["username"] == "alice"][0]
    r = a.get(f"/api/keys/public/{me['id']}")
    assert r.status_code == 200 and r.json().get("public_key_hex") is None
