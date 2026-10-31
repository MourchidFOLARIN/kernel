"""Modèles SQLAlchemy — toutes les tables du projet, créées dès l'étape 1.

Règle d'or : la table `messages` ne contient JAMAIS de texte en clair,
uniquement le chiffré (hex) et ses métadonnées (algo, mode, iv, tag).
"""
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(64), default="")
    bio: Mapped[str] = mapped_column(Text, default="")
    domain: Mapped[str] = mapped_column(String(16), default="autre")
    avatar_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="membre")  # membre|admin|attaquant
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)

    skills = relationship("UserSkill", cascade="all, delete-orphan", lazy="selectin")
    links = relationship("UserLink", cascade="all, delete-orphan", lazy="selectin")


class UserSkill(Base):
    __tablename__ = "user_skills"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    tag: Mapped[str] = mapped_column(String(32))


class UserLink(Base):
    __tablename__ = "user_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # github|portfolio
    url: Mapped[str] = mapped_column(String(255))


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    user = relationship("User", lazy="joined")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class PasswordResetCode(Base):
    __tablename__ = "password_reset_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class Contact(Base):
    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("from_id", "to_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    from_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    to_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|accepted|blocked


class Conversation(Base):
    __tablename__ = "conversations"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))  # dm|group|room
    title: Mapped[str] = mapped_column(String(80), default="")
    slug: Mapped[str | None] = mapped_column(String(80), unique=True, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(16), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class ConversationMember(Base):
    __tablename__ = "conversation_members"
    __table_args__ = (UniqueConstraint("conversation_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    last_read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Message(Base):
    """Message stocké chiffré uniquement (aucune colonne de texte en clair)."""
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    sender_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    algo: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(16), default="")
    iv_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    ciphertext_hex: Mapped[str] = mapped_column(Text)
    tag_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_to_id: Mapped[int | None] = mapped_column(ForeignKey("messages.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    edited_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Étape 4 : mode de distribution utilisé à l'envoi + empreinte publique de la clé
    # (4 premiers octets de SHA-256(clé)) pour savoir si on possède la bonne clé.
    key_dist: Mapped[str | None] = mapped_column(String(16), nullable=True)
    key_fp: Mapped[str | None] = mapped_column(String(16), nullable=True)


class MessageReaction(Base):
    __tablename__ = "message_reactions"
    __table_args__ = (UniqueConstraint("message_id", "user_id", "emoji"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    emoji: Mapped[str] = mapped_column(String(16))


class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    mime: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    ciphertext_hex: Mapped[str] = mapped_column(Text)
    iv_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    tag_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    algo: Mapped[str] = mapped_column(String(32))


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16), default="rencontre")  # rencontre|defi|atelier
    starts_at: Mapped[datetime] = mapped_column(DateTime)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class ContactMessage(Base):
    __tablename__ = "contact_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    email: Mapped[str] = mapped_column(String(254))
    subject: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(primary_key=True)
    reporter_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    target_type: Mapped[str] = mapped_column(String(16))  # message|user
    target_id: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="ouvert")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class DemoSettings(Base):
    """Singleton (id=1) : réglages de la démo de chiffrement, pilotés par l'admin."""
    __tablename__ = "demo_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    algo: Mapped[str] = mapped_column(String(32), default="Aucun")
    mode: Mapped[str] = mapped_column(String(16), default="clair")
    key_distribution: Mapped[str] = mapped_column(String(16), default="broadcast")  # broadcast|password|x25519
    broadcast_key_hex: Mapped[str | None] = mapped_column(Text, nullable=True)
    presentation_step: Mapped[int] = mapped_column(Integer, default=0)


class ActivityLog(Base):
    __tablename__ = "activity_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class MessageReceipt(Base):
    """Accusés de remise / lecture (étape 2). status : delivered|read."""
    __tablename__ = "message_receipts"
    __table_args__ = (UniqueConstraint("message_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), default="delivered")
    at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class UserPublicKey(Base):
    """Clé publique X25519 relayée par le serveur (la clé privée reste dans le navigateur)."""
    __tablename__ = "user_public_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    public_key_hex: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class ConversationSalt(Base):
    """Sel PBKDF2 public par conversation (mode « mot de passe partagé »).
    Le mot de passe et la clé dérivée ne quittent jamais le navigateur."""
    __tablename__ = "conversation_salts"
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), unique=True)
    salt_hex: Mapped[str] = mapped_column(String(64))


class GroupKeyWrap(Base):
    """Mode X25519 pour groupes/salons : la clé de groupe (aléatoire, générée dans un
    navigateur) est « emballée » (AES-GCM) pour chaque membre avec la clé X25519
    pair-à-pair expéditeur↔destinataire. Le serveur ne relaie que ces emballages."""
    __tablename__ = "group_key_wraps"
    __table_args__ = (UniqueConstraint("conversation_id", "key_fp", "recipient_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"), index=True)
    key_fp: Mapped[str] = mapped_column(String(16))
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    iv_hex: Mapped[str] = mapped_column(String(64))
    ciphertext_hex: Mapped[str] = mapped_column(String(256))
    tag_hex: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
