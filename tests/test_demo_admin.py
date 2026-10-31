"""Tests étape 3 : droits admin, réglages démo, pas de clair en base (sauf Aucun)."""
import secrets

from tests.conftest import csrf_headers


def _login(client, u, p):
    r = client.post("/api/auth/login", headers=csrf_headers(client),
                    json={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return r.json()


def _hex(s: str) -> str:
    return s.encode().hex()


def test_membre_refuse_admin(client):
    _login(client, "alice", "Alice123!")
    assert client.get("/admin", headers={"Accept": "application/json"}).status_code == 403
    assert client.get("/api/admin/demo").status_code == 403
    assert client.get("/api/admin/users").status_code == 403


def test_admin_demo_settings_broadcast(client):
    _login(client, "admin", "Admin123!")
    r = client.get("/api/admin/demo")
    assert r.status_code == 200
    data = r.json()
    assert data["key_distribution"] == "broadcast"
    assert data["broadcast_key_hex"]
    assert len(data["broadcast_key_hex"]) == 64

    # Change algo → AES-GCM
    r = client.put("/api/admin/demo", headers=csrf_headers(client),
                   json={"algo": "AES-GCM"})
    assert r.status_code == 200, r.text
    assert r.json()["algo"] == "AES-GCM"
    assert r.json()["mode"] == "GCM"

    # Nouvelle clé
    old = r.json()["broadcast_key_hex"]
    r = client.post("/api/admin/demo/new-key", headers=csrf_headers(client), json={})
    assert r.status_code == 200
    assert r.json()["broadcast_key_hex"] != old

    # Présentation jusqu'à AES-GCM (step 4)
    client.post("/api/admin/demo/presentation/reset", headers=csrf_headers(client), json={})
    for expected in ["Aucun", "César", "AES-ECB", "AES-CBC", "AES-GCM"]:
        r = client.post("/api/admin/demo/presentation/next", headers=csrf_headers(client), json={})
        # first next after reset goes to step 1 (César); we need to check progressively
    # Reset then walk
    client.post("/api/admin/demo/presentation/reset", headers=csrf_headers(client), json={})
    assert client.get("/api/admin/demo").json()["algo"] == "Aucun"
    steps = []
    for _ in range(4):
        steps.append(client.post("/api/admin/demo/presentation/next",
                                 headers=csrf_headers(client), json={}).json()["algo"])
    assert steps == ["César", "AES-ECB", "AES-CBC", "AES-GCM"]


def test_encrypted_message_not_plaintext_in_db(client):
    """Pour algo != Aucun, ciphertext_hex ne doit pas être le hex du clair."""
    _login(client, "admin", "Admin123!")
    # Force AES-CBC + clé connue
    key = "a" * 64
    from app.database import SessionLocal
    from app.models import DemoSettings
    db = SessionLocal()
    row = db.get(DemoSettings, 1)
    row.algo = "AES-CBC"
    row.mode = "CBC"
    row.broadcast_key_hex = key
    db.commit()
    db.close()

    _login(client, "alice", "Alice123!")
    # Récupère settings côté client simulant un chiffré AES-CBC via le module JS… 
    # En test Python on envoie un faux chiffré (pas le hex du clair) avec algo AES-CBC.
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    conv = client.post("/api/conversations/dm", headers=csrf_headers(client),
                       json={"user_id": bob["id"]}).json()["id"]
    plain = "message secret de test"
    fake_ct = secrets.token_hex(32)  # pas le hex du clair
    r = client.post(f"/api/messages/{conv}", headers=csrf_headers(client), json={
        "algo": "AES-CBC", "mode": "CBC", "iv": secrets.token_hex(16),
        "ciphertext": fake_ct, "tag": "",
    })
    assert r.status_code == 200, r.text

    from app.database import SessionLocal
    from app.models import Message
    db = SessionLocal()
    msg = db.scalar(__import__("sqlalchemy").select(Message).order_by(Message.id.desc()))
    assert msg.algo == "AES-CBC"
    assert msg.ciphertext_hex == fake_ct
    assert msg.ciphertext_hex != plain.encode().hex()
    assert plain.encode().hex() not in (msg.ciphertext_hex or "")
    db.close()


def test_member_can_read_demo_settings(client):
    _login(client, "alice", "Alice123!")
    r = client.get("/api/demo/settings")
    assert r.status_code == 200
    assert "broadcast_key_hex" in r.json()
