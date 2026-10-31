"""Discussion multi-membres : inscription → salons par défaut, salons, contacts, erreurs WS."""
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import csrf_headers


def _new_client():
    c = TestClient(app)
    c.__enter__()
    assert c.get("/").status_code == 200
    return c


def _register(c, name):
    r = c.post("/api/auth/register", headers=csrf_headers(c),
               json={"username": name, "email": f"{name}@exemple.fr", "password": "MotDePasse!1"})
    assert r.status_code == 200, r.text
    return c.get("/api/users/me").json()


def _hex(t):
    return t.encode().hex()


def _room(c, slug):
    return next(x for x in c.get("/api/conversations").json() if x.get("slug") == slug)


def test_register_logs_in_and_joins_default_rooms(client):
    _register(client, "nina")
    convs = client.get("/api/conversations").json()
    slugs = {c.get("slug") for c in convs if c["kind"] == "room"}
    assert {"general", "entraide"} <= slugs
    # L'historique antérieur n'est pas compté comme non lu.
    assert all(c["unread"] == 0 for c in convs)


def test_three_users_room_chat_and_history():
    a, b, c = _new_client(), _new_client(), _new_client()
    try:
        _register(a, "ana1"); _register(b, "ben1"); _register(c, "chloe1")
        gid = _room(a, "general")["id"]
        assert set(_room(a, "general")["member_ids"]) >= {
            a.get("/api/users/me").json()["id"], c.get("/api/users/me").json()["id"]}
        r = b.post(f"/api/messages/{gid}", headers=csrf_headers(b),
                   json={"algo": "Aucun", "mode": "clair", "ciphertext": _hex("salut tout le monde")})
        assert r.status_code == 200, r.text
        assert r.json()["sender_name"]
        for cl in (a, c):
            hist = cl.get(f"/api/messages/{gid}").json()
            last = hist[-1]
            assert last["ciphertext"] == _hex("salut tout le monde")
            assert last["sender_username"] == "ben1"
            assert _room(cl, "general")["unread"] == 1
    finally:
        for cl in (a, b, c):
            cl.__exit__(None, None, None)


def test_room_message_reaches_other_member_over_ws():
    a, b = _new_client(), _new_client()
    try:
        _register(a, "ana2"); _register(b, "ben2")
        gid = _room(a, "general")["id"]
        with b.websocket_connect("/ws") as ws:
            assert ws.receive_json()["type"] == "presence.list"
            a.post(f"/api/messages/{gid}", headers=csrf_headers(a),
                   json={"algo": "Aucun", "mode": "clair", "ciphertext": _hex("temps réel")})
            got = None
            for _ in range(8):
                f = ws.receive_json()
                if f.get("type") == "chat.message":
                    got = f
                    break
            assert got and got["conversation_id"] == gid and got["sender_username"] == "ana2"
    finally:
        a.__exit__(None, None, None); b.__exit__(None, None, None)


def test_ws_error_carries_client_id(client):
    _register(client, "zed1")
    with client.websocket_connect("/ws") as ws:
        ws.receive_json()
        ws.send_json({"type": "chat.send", "conversation_id": 99999, "algo": "Aucun",
                      "mode": "clair", "ciphertext": _hex("x"), "client_id": "cid-42"})
        err = None
        for _ in range(6):
            f = ws.receive_json()
            if f.get("type") == "error":
                err = f
                break
        assert err and err["client_id"] == "cid-42" and err["message"]


def test_contact_requests_flow():
    a, b = _new_client(), _new_client()
    try:
        _register(a, "ana3"); me_b = _register(b, "ben3")
        r = a.post("/api/contacts/request", headers=csrf_headers(a), json={"user_id": me_b["id"]})
        assert r.status_code == 200
        inc = [x for x in b.get("/api/contacts").json() if x["status"] == "pending" and not x["from_me"]]
        assert len(inc) == 1 and inc[0]["user"]["username"] == "ana3"
        assert b.post(f"/api/contacts/{inc[0]['id']}/accept", headers=csrf_headers(b)).status_code == 200
        assert a.get("/api/contacts").json()[0]["status"] == "accepted"
    finally:
        a.__exit__(None, None, None); b.__exit__(None, None, None)


def test_join_room_and_default_is_broadcast(client):
    _register(client, "omar1")
    s = client.get("/api/demo/settings").json()
    assert s["key_distribution"] == "broadcast"
    rooms = client.get("/api/rooms").json()
    py = next(r for r in rooms if r["slug"] == "python")
    assert client.post(f"/api/rooms/{py['id']}/join", headers=csrf_headers(client)).status_code == 200
    assert _room(client, "python")["unread"] == 0


def test_app_page_has_home_and_new_chat(client):
    _register(client, "lea1")
    html = client.get("/app").text
    for needle in ("Nouveau message", "newmsg-dlg", "Ouvrir #général", "Demandes", "conn-status", "req-in"):
        assert needle in html
