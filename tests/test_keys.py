"""Étape 4 : relais des éléments publics de clés ; le serveur ne stocke ni mot de passe ni clé privée."""
import secrets

from sqlalchemy import inspect, select

from tests.conftest import csrf_headers


def _login(client, u, p):
    assert client.post("/api/auth/login", headers=csrf_headers(client),
                       json={"username": u, "password": p}).status_code == 200


def _dm(client):
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    return client.post("/api/conversations/dm", headers=csrf_headers(client),
                       json={"user_id": bob["id"]}).json()["id"], bob["id"]


def test_public_key_relay(client):
    _login(client, "alice", "Alice123!")
    pub = secrets.token_hex(32)
    r = client.post("/api/keys/public", headers=csrf_headers(client), json={"public_key_hex": pub})
    assert r.status_code == 200
    me = client.get("/api/auth/me").json()["id"]
    assert client.get(f"/api/keys/public/{me}").json()["public_key_hex"] == pub
    bad = client.post("/api/keys/public", headers=csrf_headers(client), json={"public_key_hex": "zz"})
    assert bad.status_code == 422


def test_public_key_via_ws(client):
    _login(client, "alice", "Alice123!")
    _, bob_id = _dm(client)
    pub = secrets.token_hex(32)
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "key.public", "public_key_hex": pub})
        ws.send_json({"type": "key.request", "user_id": bob_id})
        for _ in range(6):
            f = ws.receive_json()
            if f["type"] == "error" and f["code"] == "key_missing":
                break
        else:
            raise AssertionError("pas de réponse key.request")
    me = client.get("/api/auth/me").json()["id"]
    assert client.get(f"/api/keys/public/{me}").json()["public_key_hex"] == pub


def test_salt_members_only(client):
    _login(client, "alice", "Alice123!")
    conv, _ = _dm(client)
    s1 = client.get(f"/api/keys/salt/{conv}").json()["salt"]
    assert s1 == client.get(f"/api/keys/salt/{conv}").json()["salt"]
    assert len(s1) == 32
    client.post("/api/auth/logout", headers=csrf_headers(client), json={})
    _login(client, "admin", "Admin123!")
    assert client.get(f"/api/keys/salt/{conv}").status_code == 403


def test_no_secret_columns_in_schema(client):
    """Aucune colonne de la base ne peut contenir mot de passe partagé, clé dérivée ou clé privée."""
    from app.database import engine
    insp = inspect(engine)
    for table in insp.get_table_names():
        for col in insp.get_columns(table):
            name = col["name"].lower()
            assert "private" not in name and "derived" not in name and "shared" not in name, (table, name)
            if table != "users":
                assert "password" not in name, (table, name)


def test_message_keeps_key_dist(client):
    _login(client, "alice", "Alice123!")
    conv, _ = _dm(client)
    r = client.post(f"/api/messages/{conv}", headers=csrf_headers(client), json={
        "algo": "AES-GCM", "mode": "GCM", "iv": secrets.token_hex(12),
        "ciphertext": secrets.token_hex(20), "tag": secrets.token_hex(16),
        "key_dist": "x25519", "key_fp": "a1b2c3d4"})
    assert r.status_code == 200, r.text
    m = client.get(f"/api/messages/{conv}").json()[-1]
    assert m["key_dist"] == "x25519" and m["key_fp"] == "a1b2c3d4"
    bad = client.post(f"/api/messages/{conv}", headers=csrf_headers(client), json={
        "algo": "AES-GCM", "ciphertext": "00", "key_dist": "magie"})
    assert bad.status_code == 400


def test_presentation_last_step_is_ecdh(client):
    _login(client, "admin", "Admin123!")
    r = client.put("/api/admin/demo", headers=csrf_headers(client), json={"presentation_step": 5})
    assert r.json()["key_distribution"] == "x25519" and r.json()["algo"] == "AES-GCM"
    r = client.put("/api/admin/demo", headers=csrf_headers(client), json={"presentation_step": 4})
    assert r.json()["key_distribution"] == "broadcast"
