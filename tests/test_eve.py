"""Étape 5 : espace attaquant Ève — droits, interception, DEMO_MODE."""
from itsdangerous import URLSafeSerializer

from tests.conftest import csrf_headers


def _login(client, u, p):
    r = client.post("/api/auth/login", headers=csrf_headers(client),
                    json={"username": u, "password": p})
    assert r.status_code == 200, r.text


def _hex(s: str) -> str:
    return s.encode().hex()


def test_membre_refuse_eve(client):
    _login(client, "alice", "Alice123!")
    assert client.get("/eve", headers={"Accept": "application/json"}).status_code == 403
    assert client.get("/api/eve/recent").status_code == 403


def test_admin_refuse_eve(client):
    _login(client, "admin", "Admin123!")
    assert client.get("/eve", headers={"Accept": "application/json"}).status_code == 403


def test_attaquant_ok(client):
    _login(client, "eve", "Eve123!")
    r = client.get("/eve")
    assert r.status_code == 200
    assert "Espace attaquant" in r.text
    assert client.get("/api/eve/settings").status_code == 200
    assert client.get("/api/eve/recent").status_code == 200


def _drain_until(ws, typ, n=12):
    for _ in range(n):
        f = ws.receive_json()
        if f.get("type") == typ:
            return f
    raise AssertionError(f"pas de trame {typ}")


def test_interception_hold_forward_reject(client):
    from app.ws.hub import eve

    eve.intercept = False
    eve.held.clear()

    _login(client, "alice", "Alice123!")
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    conv = client.post("/api/conversations/dm", headers=csrf_headers(client),
                       json={"user_id": bob["id"]}).json()["id"]
    client.post("/api/auth/logout", headers=csrf_headers(client), json={})

    _login(client, "eve", "Eve123!")
    with client.websocket_connect("/ws") as eve_ws:
        _drain_until(eve_ws, "demo.settings")
        eve_ws.send_json({"type": "eve.intercept", "active": True})
        assert _drain_until(eve_ws, "eve.mode")["intercept"] is True
        assert eve.intercept is True

        from fastapi.testclient import TestClient
        from app.main import app
        from app import config
        from app.security import CSRF_COOKIE

        with TestClient(app) as alice:
            alice.get("/")
            seed = alice.cookies.get(CSRF_COOKIE)
            tok = URLSafeSerializer(config.SECRET_KEY, salt="kernel-csrf").dumps(seed)
            hdr = {"X-CSRF-Token": tok, "Content-Type": "application/json"}
            alice.post("/api/auth/login", headers=hdr,
                       json={"username": "alice", "password": "Alice123!"})
            sent = alice.post(f"/api/messages/{conv}", headers=hdr, json={
                "algo": "Aucun", "mode": "clair", "ciphertext": _hex("secret pour bob"),
            })
            assert sent.status_code == 200, sent.text
            assert sent.json().get("held")

            held = _drain_until(eve_ws, "eve.held")
            hid = held["hold_id"]
            assert hid in eve.held

            eve_ws.send_json({"type": "eve.reject", "hold_id": hid})
            assert _drain_until(eve_ws, "eve.resolved")["action"] == "reject"
            assert hid not in eve.held

            sent2 = alice.post(f"/api/messages/{conv}", headers=hdr, json={
                "algo": "Aucun", "mode": "clair", "ciphertext": _hex("original"),
            })
            assert sent2.status_code == 200
            held = _drain_until(eve_ws, "eve.held")
            hid = held["hold_id"]
            eve_ws.send_json({"type": "eve.modify", "hold_id": hid, "ciphertext": _hex("tampered!")})
            resolved = _drain_until(eve_ws, "eve.resolved")
            assert resolved["action"] == "forward" and resolved.get("tampered") is True
            assert hid not in eve.held

    eve.intercept = False


def test_demo_mode_false_blocks_eve(client, monkeypatch):
    import app.config as cfg
    import app.deps as deps
    monkeypatch.setattr(cfg, "DEMO_MODE", False)
    monkeypatch.setattr(deps.config, "DEMO_MODE", False)
    _login(client, "eve", "Eve123!")
    assert client.get("/eve", headers={"Accept": "application/json"}).status_code == 404
    assert client.get("/api/eve/recent").status_code == 404


def test_demo_mode_false_hides_broadcast_key(client, monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg, "DEMO_MODE", False)
    _login(client, "alice", "Alice123!")
    s = client.get("/api/demo/settings").json()
    assert s.get("broadcast_key_hex") in (None, "")
    assert s["key_distribution"] != "broadcast"
