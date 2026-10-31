"""Logique métier de la messagerie (partagée entre REST et WebSocket).

ÉTAPE 2 — messages EN CLAIR : le client envoie `ciphertext` = texte UTF-8
encodé en hexadécimal, avec algo="Aucun", mode="clair", iv/tag vides.
Le serveur stocke ce hex tel quel dans `messages.ciphertext_hex`, sans jamais
le décoder. À l'étape 3, le client enverra un vrai chiffré dans le même champ :
le serveur et le format ne changent pas.
"""
import re
from datetime import datetime

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session as DbSession

from app.models import (Attachment, Contact, Conversation, ConversationMember, Message,
                        MessageReaction, MessageReceipt, User, now_utc)

HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
MAX_HEX = 16000  # ~8 Ko de texte
MAX_ATTACHMENT_HEX = 2_000_000  # ~1 Mo chiffré (fichier ≤ ~700 Ko avant base64)
ALLOWED_ALGOS = {
    "Aucun", "César", "Vigenère", "XOR", "RC4",
    "DES-ECB", "DES-CBC", "3DES-CBC",
    "AES-ECB", "AES-CBC", "AES-CTR", "AES-GCM",
    "ChaCha20-Poly1305",
}


class ChatError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def is_member(db: DbSession, conv_id: int, user_id: int) -> bool:
    return db.scalar(select(ConversationMember.id).where(
        ConversationMember.conversation_id == conv_id,
        ConversationMember.user_id == user_id)) is not None


def member_ids(db: DbSession, conv_id: int) -> list[int]:
    return list(db.scalars(select(ConversationMember.user_id).where(
        ConversationMember.conversation_id == conv_id)))


def is_blocked(db: DbSession, a: int, b: int) -> bool:
    """True si a a bloqué b ou b a bloqué a."""
    return db.scalar(select(Contact.id).where(
        Contact.status == "blocked",
        ((Contact.from_id == a) & (Contact.to_id == b)) | ((Contact.from_id == b) & (Contact.to_id == a)))) is not None


def find_or_create_dm(db: DbSession, me: User, other_id: int) -> Conversation:
    if is_blocked(db, me.id, other_id):
        raise ChatError("forbidden", "Conversation impossible avec ce membre.")
    if other_id == me.id:
        raise ChatError("validation", "Impossible d'ouvrir une conversation avec soi-même.")
    other = db.get(User, other_id)
    if not other or other.is_suspended:
        raise ChatError("not_found", "Membre introuvable.")
    a = ConversationMember.__table__.alias("a")
    b = ConversationMember.__table__.alias("b")
    existing = db.scalar(
        select(Conversation).join(a, a.c.conversation_id == Conversation.id)
        .join(b, b.c.conversation_id == Conversation.id)
        .where(Conversation.kind == "dm", a.c.user_id == me.id, b.c.user_id == other_id))
    if existing:
        return existing
    conv = Conversation(kind="dm", title="", created_by=me.id)
    db.add(conv)
    db.flush()
    db.add_all([ConversationMember(conversation_id=conv.id, user_id=me.id),
                ConversationMember(conversation_id=conv.id, user_id=other_id)])
    db.commit()
    return conv


def save_message(db: DbSession, sender: User, data: dict) -> Message:
    """Valide et enregistre un message (format chat.send)."""
    try:
        conv_id = int(data.get("conversation_id"))
    except (TypeError, ValueError):
        raise ChatError("validation", "conversation_id invalide.")
    if not is_member(db, conv_id, sender.id):
        raise ChatError("forbidden", "Vous ne participez pas à cette conversation.")
    algo = str(data.get("algo") or "Aucun")
    if algo not in ALLOWED_ALGOS:
        raise ChatError("validation", "algo non supporté à cette étape.")
    ct = str(data.get("ciphertext") or "")
    if not ct or len(ct) > MAX_HEX or len(ct) % 2 or not HEX_RE.match(ct):
        raise ChatError("validation", "ciphertext doit être une chaîne hexadécimale non vide.")
    iv, tag = data.get("iv") or None, data.get("tag") or None
    for v in (iv, tag):
        if v is not None and (not isinstance(v, str) or len(v) > 512 or not HEX_RE.match(v)):
            raise ChatError("validation", "iv/tag invalides.")
    key_dist = data.get("key_dist") or None
    if key_dist is not None and key_dist not in ("broadcast", "password", "x25519"):
        raise ChatError("validation", "key_dist invalide.")
    key_fp = data.get("key_fp") or None
    if key_fp is not None and (not isinstance(key_fp, str) or len(key_fp) > 16 or not HEX_RE.match(key_fp)):
        raise ChatError("validation", "key_fp invalide.")
    conv = db.get(Conversation, conv_id)
    if conv.kind == "dm":
        others = [m for m in member_ids(db, conv_id) if m != sender.id]
        if others and is_blocked(db, sender.id, others[0]):
            raise ChatError("forbidden", "Vous ne pouvez plus écrire à ce membre.")
    reply_to = data.get("reply_to")
    if isinstance(reply_to, int):
        parent = db.get(Message, reply_to)
        if not parent or parent.conversation_id != conv_id:
            reply_to = None
    att = data.get("attachment")
    if att is not None:
        if not isinstance(att, dict):
            raise ChatError("validation", "Pièce jointe invalide.")
        a_ct = str(att.get("ciphertext") or "")
        if not a_ct or len(a_ct) > MAX_ATTACHMENT_HEX or len(a_ct) % 2 or not HEX_RE.match(a_ct):
            raise ChatError("validation", "Pièce jointe trop volumineuse ou invalide (max ~700 Ko).")
    msg = Message(conversation_id=conv_id, sender_id=sender.id, algo=algo,
                  mode=str(data.get("mode") or "clair")[:16], iv_hex=iv,
                  ciphertext_hex=ct.lower(), tag_hex=tag, key_dist=key_dist, key_fp=key_fp,
                  reply_to_id=int(reply_to) if isinstance(reply_to, int) else None)
    db.add(msg)
    # L'expéditeur a « lu » sa propre conversation.
    mem = db.scalar(select(ConversationMember).where(
        ConversationMember.conversation_id == conv_id, ConversationMember.user_id == sender.id))
    db.flush()
    mem.last_read_at = msg.created_at
    if att is not None:
        # Nom et type réels sont DANS le blob chiffré ; le serveur ne voit que la taille.
        db.add(Attachment(message_id=msg.id, filename="fichier", mime="application/octet-stream",
                          size=len(a_ct) // 2, ciphertext_hex=a_ct.lower(),
                          iv_hex=(att.get("iv") or None), tag_hex=(att.get("tag") or None),
                          algo=algo))
    db.commit()
    return msg


def reactions_of(db: DbSession, msg_id: int) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for emoji, uid in db.execute(select(MessageReaction.emoji, MessageReaction.user_id)
                                 .where(MessageReaction.message_id == msg_id)).all():
        out.setdefault(emoji, []).append(uid)
    return out


def enrich(db: DbSession, msg: Message, out: dict) -> dict:
    """Ajoute réactions et pièce jointe (métadonnées) à un message sérialisé."""
    out["reactions"] = reactions_of(db, msg.id)
    att = db.scalar(select(Attachment).where(Attachment.message_id == msg.id))
    out["attachment"] = {"id": att.id, "size": att.size} if att else None
    sender = db.get(User, msg.sender_id)
    out["sender_name"] = (sender.display_name or sender.username) if sender else "Membre supprimé"
    out["sender_username"] = sender.username if sender else ""
    return out


def message_out(msg: Message, status: str | None = None, client_id: str | None = None) -> dict:
    if msg.deleted_at:
        return {"type": "chat.message", "id": msg.id, "conversation_id": msg.conversation_id,
                "sender_id": msg.sender_id, "deleted": True, "algo": "Aucun", "mode": "clair",
                "iv": "", "ciphertext": "", "tag": "", "created_at": iso(msg.created_at),
                "reply_to": msg.reply_to_id}
    out = {"type": "chat.message", "id": msg.id, "conversation_id": msg.conversation_id,
           "sender_id": msg.sender_id, "algo": msg.algo, "mode": msg.mode,
           "iv": msg.iv_hex or "", "ciphertext": msg.ciphertext_hex, "tag": msg.tag_hex or "",
           "reply_to": msg.reply_to_id, "created_at": iso(msg.created_at),
           "key_dist": msg.key_dist, "key_fp": msg.key_fp,
           "edited_at": iso(msg.edited_at)}
    if status:
        out["status"] = status
    if client_id:
        out["client_id"] = client_id
    return out


def record_receipt(db: DbSession, user: User, message_id: int, status: str) -> tuple[Message, list[int]] | None:
    """Enregistre delivered/read. Pour « read », marque aussi tous les messages
    antérieurs et met à jour last_read_at. Retourne (message, ids marqués)."""
    if status not in ("delivered", "read"):
        raise ChatError("validation", "status invalide.")
    msg = db.get(Message, message_id)
    if not msg or not is_member(db, msg.conversation_id, user.id):
        raise ChatError("forbidden", "Message inaccessible.")
    if msg.sender_id == user.id:
        return None
    if status == "read":
        targets = list(db.scalars(select(Message).where(
            Message.conversation_id == msg.conversation_id, Message.id <= msg.id,
            Message.sender_id != user.id)))
        mem = db.scalar(select(ConversationMember).where(
            ConversationMember.conversation_id == msg.conversation_id,
            ConversationMember.user_id == user.id))
        if not mem.last_read_at or mem.last_read_at < msg.created_at:
            mem.last_read_at = msg.created_at
    else:
        targets = [msg]
    marked = []
    for m in targets:
        r = db.scalar(select(MessageReceipt).where(
            MessageReceipt.message_id == m.id, MessageReceipt.user_id == user.id))
        if r is None:
            db.add(MessageReceipt(message_id=m.id, user_id=user.id, status=status))
            marked.append(m.id)
        elif status == "read" and r.status != "read":
            r.status, r.at = "read", now_utc()
            marked.append(m.id)
    db.commit()
    return msg, marked


def receipt_status_for(db: DbSession, msg_ids: list[int], me_id: int) -> dict[int, str]:
    """Statut agrégé (sent/delivered/read) des messages que J'AI envoyés."""
    if not msg_ids:
        return {}
    rows = db.execute(select(MessageReceipt.message_id, MessageReceipt.status)
                      .where(MessageReceipt.message_id.in_(msg_ids),
                             MessageReceipt.user_id != me_id)).all()
    out: dict[int, str] = {}
    for mid, st in rows:
        if st == "read" or out.get(mid) != "read":
            out[mid] = st
    return out


def history(db: DbSession, user: User, conv_id: int, before: int | None = None, limit: int = 50):
    if not is_member(db, conv_id, user.id):
        raise ChatError("forbidden", "Vous ne participez pas à cette conversation.")
    q = select(Message).where(Message.conversation_id == conv_id)
    if before:
        q = q.where(Message.id < before)
    msgs = list(reversed(db.scalars(q.order_by(Message.id.desc()).limit(limit)).all()))
    mine = [m.id for m in msgs if m.sender_id == user.id]
    st = receipt_status_for(db, mine, user.id)
    return [enrich(db, m, message_out(m, st.get(m.id, "sent") if m.sender_id == user.id else None))
            for m in msgs]


def unread_count(db: DbSession, conv_id: int, user_id: int, last_read: datetime | None) -> int:
    q = select(func.count()).select_from(Message).where(
        Message.conversation_id == conv_id, Message.sender_id != user_id,
        Message.deleted_at.is_(None))
    if last_read:
        q = q.where(Message.created_at > last_read)
    return db.scalar(q) or 0


def list_conversations(db: DbSession, user: User, online: set[int]) -> list[dict]:
    """DM, groupes privés et salons rejoints."""
    rows = db.execute(select(Conversation, ConversationMember.last_read_at)
                      .join(ConversationMember, and_(ConversationMember.conversation_id == Conversation.id,
                                                     ConversationMember.user_id == user.id))).all()
    out = []
    for conv, last_read in rows:
        mids = member_ids(db, conv.id)
        other = None
        if conv.kind == "dm":
            other_id = next((i for i in mids if i != user.id), None)
            o = db.get(User, other_id) if other_id else None
            if o:
                other = {"id": o.id, "username": o.username,
                         "display_name": o.display_name or o.username,
                         "online": o.id in online, "avatar": o.avatar_path}
        last = db.scalar(select(Message).where(Message.conversation_id == conv.id,
                                               Message.deleted_at.is_(None))
                         .order_by(Message.id.desc()).limit(1))
        out.append({
            "id": conv.id, "kind": conv.kind, "title": conv.title, "slug": conv.slug,
            "created_by": conv.created_by, "member_ids": mids,
            "other": other,
            "last_message": message_out(last) if last else None,
            "unread": unread_count(db, conv.id, user.id, last_read),
            "updated_at": iso(last.created_at if last else conv.created_at),
        })
    out.sort(key=lambda c: c["updated_at"] or "", reverse=True)
    return out


DEFAULT_ROOM_SLUGS = ("general", "entraide")


def ensure_default_rooms(db: DbSession, user) -> list[int]:
    """Inscrit le membre aux salons par défaut (#général, #entraide). Idempotent."""
    from app.models import Conversation, ConversationMember
    joined = []
    for slug in DEFAULT_ROOM_SLUGS:
        room = db.scalar(select(Conversation).where(Conversation.slug == slug,
                                                    Conversation.kind == "room"))
        if not room or is_member(db, room.id, user.id):
            continue
        db.add(ConversationMember(conversation_id=room.id, user_id=user.id, last_read_at=now_utc()))
        joined.append(room.id)
    if joined:
        db.flush()
    return joined
