"""Comptes et salons de démonstration (idempotent)."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (Conversation, ConversationMember, DemoSettings, User,
                        UserLink, UserSkill)
import secrets
from app.security import hash_password

# Mots de passe documentés dans le README.
SEED_ACCOUNTS = [
    {"username": "alice", "email": "alice@kernel.local", "password": "Alice123!",
     "role": "membre", "display_name": "Alice Martin", "domain": "dev",
     "bio": "Développeuse full-stack. Fan de FastAPI, TypeScript et de bons coffee-chat.",
     "skills": ["python", "fastapi", "typescript", "react"],
     "links": [("github", "https://github.com/example-alice"),
               ("portfolio", "https://alice.dev.example")]},
    {"username": "bob", "email": "bob@kernel.local", "password": "Bob123!",
     "role": "membre", "display_name": "Bob Dupont", "domain": "cyber",
     "bio": "Passionné de cybersécurité offensive (éthique) et de CTF le week-end.",
     "skills": ["pentest", "network", "linux", "python"],
     "links": [("github", "https://github.com/example-bob")]},
    {"username": "admin", "email": "admin@kernel.local", "password": "Admin123!",
     "role": "admin", "display_name": "Admin Kernel", "domain": "autre",
     "bio": "Compte administrateur de la plateforme.", "skills": [], "links": []},
    {"username": "eve", "email": "eve@kernel.local", "password": "Eve123!",
     "role": "attaquant", "display_name": "Ève", "domain": "cyber",
     "bio": "Compte de démonstration.",
     "skills": [], "links": []},
]

ROOMS = [
    ("général", "general", "autre", "Discussions générales, annonces et présentations."),
    ("dev-web", "dev-web", "dev", "HTML, CSS, JS, frameworks web, accessibilité."),
    ("python", "python", "dev", "Python, ses libs, ses pièges et ses bonnes pratiques."),
    ("cybersécurité", "cybersecurite", "cyber", "Sécurité offensive et défensive, dans un cadre éthique."),
    ("data-science", "data-science", "data", "Analyse de données, visualisation, stats."),
    ("ia", "ia", "ia", "Machine learning, LLM, MLOps."),
    ("devops", "devops", "devops", "CI/CD, conteneurs, cloud, observabilité."),
    ("entraide", "entraide", "autre", "Besoin d'un coup de main ? Posez votre question ici."),
    ("projets", "projets", "autre", "Side-projects, collabs, recherches de coéquipiers."),
    ("offres-et-opportunités", "offres-et-opportunites", "autre",
     "Stages, jobs, freelance, appels à projets."),
]


def seed(db: Session) -> None:
    for acc in SEED_ACCOUNTS:
        if db.scalar(select(User).where(User.username == acc["username"])):
            continue
        user = User(username=acc["username"], email=acc["email"],
                    password_hash=hash_password(acc["password"]),
                    display_name=acc["display_name"], bio=acc["bio"],
                    domain=acc["domain"], role=acc["role"], email_verified=True)
        db.add(user)
        db.flush()
        for tag in acc["skills"]:
            db.add(UserSkill(user_id=user.id, tag=tag))
        for kind, url in acc["links"]:
            db.add(UserLink(user_id=user.id, kind=kind, url=url))

    admin = db.scalar(select(User).where(User.username == "admin"))
    for title, slug, domain, desc in ROOMS:
        if db.scalar(select(Conversation).where(Conversation.slug == slug)):
            continue
        room = Conversation(kind="room", title=f"#{title}", slug=slug, domain=domain,
                            description=desc, created_by=admin.id if admin else None)
        db.add(room)
        db.flush()
        # Alice et Bob rejoignent quelques salons pour que les compteurs ne soient pas à zéro.
        for uname in ("alice", "bob"):
            u = db.scalar(select(User).where(User.username == uname))
            if u:
                db.add(ConversationMember(conversation_id=room.id, user_id=u.id))

    db.flush()
    # Tous les comptes (y compris existants) sont membres de #général et #entraide.
    from app.chat import ensure_default_rooms
    from app.models import ConversationMember as CM
    for u in db.scalars(select(User)).all():
        has_room = db.scalar(select(CM.id).join(Conversation, Conversation.id == CM.conversation_id)
                             .where(CM.user_id == u.id, Conversation.kind == "room").limit(1))
        if not has_room:  # ne ré-inscrit pas quelqu'un qui a volontairement quitté
            ensure_default_rooms(db, u)

    if not db.get(DemoSettings, 1):
        db.add(DemoSettings(id=1, algo="Aucun", mode="clair",
                            key_distribution="broadcast",
                            broadcast_key_hex=secrets.token_hex(32), presentation_step=0))
    # Garantit une clé broadcast même si la ligne existait déjà sans clé.
    row = db.get(DemoSettings, 1)
    if row and not row.broadcast_key_hex:
        row.broadcast_key_hex = secrets.token_hex(32)
    db.commit()
