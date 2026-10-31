"""Tests d'authentification et de droits."""
from tests.conftest import csrf_headers


def test_register_and_me(client):
    r = client.post("/api/auth/register", headers=csrf_headers(client), json={
        "username": "charlie", "email": "charlie@example.com",
        "password": "Charlie1!", "domain": "dev",
    })
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "charlie"
    me = client.get("/api/auth/me")
    assert me.json()["authenticated"] is True
    assert me.json()["username"] == "charlie"


def test_login_seed_alice(client):
    r = client.post("/api/auth/login", headers=csrf_headers(client), json={
        "username": "alice", "password": "Alice123!",
    })
    assert r.status_code == 200
    assert r.json()["role"] == "membre"


def test_login_wrong_password(client):
    r = client.post("/api/auth/login", headers=csrf_headers(client), json={
        "username": "alice", "password": "mauvais",
    })
    assert r.status_code == 401


def test_admin_vs_membre(client):
    # Membre → /admin = 403 (HTML ou JSON selon Accept)
    client.post("/api/auth/login", headers=csrf_headers(client), json={
        "username": "alice", "password": "Alice123!",
    })
    r = client.get("/admin", headers={"Accept": "application/json"})
    assert r.status_code == 403

    client.post("/api/auth/logout", headers=csrf_headers(client), json={})
    # Admin → /admin = 200
    client.post("/api/auth/login", headers=csrf_headers(client), json={
        "username": "admin", "password": "Admin123!",
    })
    r = client.get("/admin")
    assert r.status_code == 200


def test_duplicate_username(client):
    r = client.post("/api/auth/register", headers=csrf_headers(client), json={
        "username": "alice", "email": "autre@example.com",
        "password": "Autre123!", "domain": "dev",
    })
    assert r.status_code == 400


def test_forgot_shows_code(client):
    r = client.post("/api/auth/forgot", headers=csrf_headers(client), json={"username": "bob"})
    assert r.status_code == 200
    data = r.json()
    assert data["found"] is True
    assert len(data["code"]) == 6
