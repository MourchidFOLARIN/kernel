"""Tests messagerie étape 2 : DM, historique, droits, WebSocket."""
import json

from tests.conftest import csrf_headers


def _login(client, username, password):
    r = client.post("/api/auth/login", headers=csrf_headers(client),
                    json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _hex(text: str) -> str:
    return text.encode().hex()


def test_open_dm_and_send_rest(client):
    _login(client, "alice", "Alice123!")
    # Bob a l'id 2 dans le seed
    directory = client.get("/api/users/directory?q=bob")
    assert directory.status_code == 200
    bob = next(u for u in directory.json() if u["username"] == "bob")
    dm = client.post("/api/conversations/dm", headers=csrf_headers(client),
                     json={"user_id": bob["id"]})
    assert dm.status_code == 200
    conv_id = dm.json()["id"]
    # Idempotent
    dm2 = client.post("/api/conversations/dm", headers=csrf_headers(client),
                      json={"user_id": bob["id"]})
    assert dm2.json()["id"] == conv_id

    sent = client.post(f"/api/messages/{conv_id}", headers=csrf_headers(client), json={
        "algo": "Aucun", "mode": "clair", "ciphertext": _hex("Salut Bob !"),
    })
    assert sent.status_code == 200, sent.text
    assert sent.json()["algo"] == "Aucun"
    assert sent.json()["ciphertext"] == _hex("Salut Bob !")

    hist = client.get(f"/api/messages/{conv_id}")
    assert hist.status_code == 200
    assert len(hist.json()) == 1
    assert hist.json()[0]["ciphertext"] == _hex("Salut Bob !")


def test_cannot_read_others_history(client):
    _login(client, "alice", "Alice123!")
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    conv_id = client.post("/api/conversations/dm", headers=csrf_headers(client),
                          json={"user_id": bob["id"]}).json()["id"]
    client.post(f"/api/messages/{conv_id}", headers=csrf_headers(client),
                json={"ciphertext": _hex("secret")})
    # Admin n'est pas membre → 403
    client.post("/api/auth/logout", headers=csrf_headers(client), json={})
    _login(client, "admin", "Admin123!")
    r = client.get(f"/api/messages/{conv_id}")
    assert r.status_code == 403


def test_list_conversations(client):
    _login(client, "alice", "Alice123!")
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    client.post("/api/conversations/dm", headers=csrf_headers(client), json={"user_id": bob["id"]})
    convs = client.get("/api/conversations")
    assert convs.status_code == 200
    assert any(c["other"]["username"] == "bob" for c in convs.json())


def test_websocket_chat_send(client):
    _login(client, "alice", "Alice123!")
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    conv_id = client.post("/api/conversations/dm", headers=csrf_headers(client),
                          json={"user_id": bob["id"]}).json()["id"]
    with client.websocket_connect("/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "presence.list"
        assert isinstance(hello["online"], list)
        # La diffusion « presence » (soi-même en ligne) peut arriver juste après.
        ws.send_json({
            "type": "chat.send", "conversation_id": conv_id,
            "algo": "Aucun", "mode": "clair",
            "ciphertext": _hex("via ws"), "client_id": "test-1",
        })
        echo = None
        for _ in range(5):
            frame = ws.receive_json()
            if frame.get("type") == "chat.message":
                echo = frame
                break
        assert echo is not None, "pas d'écho chat.message"
        assert echo["ciphertext"] == _hex("via ws")
        assert echo["status"] == "sent"
        assert echo["client_id"] == "test-1"
    # Persisté
    hist = client.get(f"/api/messages/{conv_id}").json()
    assert any(m["ciphertext"] == _hex("via ws") for m in hist)


def test_ws_unauthenticated_rejected(client):
    # Nouveau client sans cookie de session
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as naked:
        try:
            with naked.websocket_connect("/ws") as ws:
                ws.receive_json()
                assert False, "devrait être refusé"
        except Exception:
            pass  # fermeture attendue (4401)


def test_mark_read(client):
    _login(client, "alice", "Alice123!")
    bob = next(u for u in client.get("/api/users/directory?q=bob").json() if u["username"] == "bob")
    conv_id = client.post("/api/conversations/dm", headers=csrf_headers(client),
                          json={"user_id": bob["id"]}).json()["id"]
    mid = client.post(f"/api/messages/{conv_id}", headers=csrf_headers(client),
                      json={"ciphertext": _hex("à lire")}).json()["id"]
    client.post("/api/auth/logout", headers=csrf_headers(client), json={})
    _login(client, "bob", "Bob123!")
    r = client.post(f"/api/messages/{mid}/read", headers=csrf_headers(client))
    assert r.status_code == 200
