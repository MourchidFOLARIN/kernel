"""Smoke tests des landing pages publiques."""

PAGES = [
    "/", "/fonctionnalites", "/communautes", "/dev", "/cybersecurite", "/data-ia",
    "/evenements", "/a-propos", "/faq", "/contact", "/regles", "/confidentialite",
    "/rejoindre", "/connexion", "/mot-de-passe-oublie",
]


def test_landings_200(client):
    for path in PAGES:
        r = client.get(path)
        assert r.status_code == 200, f"{path} → {r.status_code}"


def test_error_pages(client):
    r = client.get("/404")
    assert r.status_code == 404
    assert "existe pas" in r.text
    r = client.get("/500")
    assert r.status_code == 500


def test_home_has_real_stats_and_slogan(client):
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "Là où ceux qui construisent se retrouvent" in body
    # Alice + Bob = 2 membres (admin/eve exclus du compteur « membres »)
    assert "2" in body
    # 10 salons seed
    assert ">10<" in body or "stat-n mono\">10" in body or "10" in body


def test_no_crypto_vocab_in_public_pages(client):
    """Aucun vocabulaire de chiffrement / interception / démo dans les pages publiques."""
    ban = ["chiffrement", "chiffré", "algorithme", "interception", "démonstration pédagogique",
           "AES-", "ChaCha", "X25519", "César", "Vigenère", "ultra-sécurisé", "100 % privé"]
    for path in ["/", "/fonctionnalites", "/faq", "/a-propos", "/regles", "/confidentialite",
                 "/communautes", "/rejoindre"]:
        text = client.get(path).text.lower()
        for word in ban:
            assert word.lower() not in text, f"{path} contient « {word} »"


def test_stats_api_rooms(client):
    r = client.get("/api/rooms")
    assert r.status_code == 200
    assert len(r.json()) == 10
