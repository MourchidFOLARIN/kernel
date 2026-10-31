"""Aucun vocabulaire chiffrement / démo / interception dans content/ et pages publiques."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTENT = ROOT / "content"
PUBLIC_TEMPLATES = [
    "base.html", "home.html", "features.html", "communities.html", "landing.html",
    "events.html", "about.html", "faq.html", "contact.html", "prose.html",
    "join.html", "login.html", "forgot.html", "error.html", "app.html",
]
BANNED = [
    "chiffrement", "chiffré", "chiffrée", "déchiffrement", "algorithme",
    "interception", "intercepter", "démonstration pédagogique",
    "aes-", "chacha", "x25519", "césar", "vigenère", "pbkdf2",
    "ultra-sécurisé", "ultra-securise", "100 % privé", "100% privé", "100% prive",
    "coulisses",
]


def _iter_public_texts():
    for p in CONTENT.rglob("*"):
        if p.suffix in (".json", ".md"):
            yield p, p.read_text(encoding="utf-8")
    tpl = ROOT / "app" / "templates"
    for name in PUBLIC_TEMPLATES:
        path = tpl / name
        yield path, path.read_text(encoding="utf-8")


def test_no_crypto_vocab_in_public_sources():
    offenders = []
    for path, raw in _iter_public_texts():
        # Retire les faux positifs « en chiffres »
        text = raw.lower().replace("en chiffres", "")
        for word in BANNED:
            if word in text:
                offenders.append(f"{path.relative_to(ROOT)} → « {word} »")
    assert not offenders, "Vocabulaire interdit :\n- " + "\n- ".join(offenders)


def test_public_pages_seo_and_landmarks(client):
    pages = ["/", "/fonctionnalites", "/communautes", "/dev", "/cybersecurite",
             "/data-ia", "/evenements", "/a-propos", "/faq", "/contact",
             "/regles", "/confidentialite", "/rejoindre", "/connexion"]
    for path in pages:
        r = client.get(path)
        assert r.status_code == 200, path
        b = r.text
        assert "<title>" in b and 'name="description"' in b and 'property="og:title"' in b
        assert 'lang="fr"' in b and "<main" in b and "<nav" in b and "<footer" in b


def test_error_pages(client):
    assert client.get("/404").status_code == 404
    assert client.get("/500").status_code == 500
    assert client.get("/page-qui-nexiste-pas").status_code == 404
