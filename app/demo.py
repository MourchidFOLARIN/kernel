"""Réglages de démonstration (singleton demo_settings) et scénario de présentation.

Distribution des clés : broadcast (clé en clair, faille volontaire), password (PBKDF2 côté navigateur), x25519 (ECDH côté navigateur).
Les trois modes de distribution sont opérationnels (étape 4).
"""
import secrets


from sqlalchemy.orm import Session as DbSession

from app.models import ActivityLog, DemoSettings

# algo stocké = libellé côté client (ALGOS keys)
PRESENTATION = [
    {"step": 0, "algo": "Aucun", "label": "Clair (Aucun)"},
    {"step": 1, "algo": "César", "label": "César"},
    {"step": 2, "algo": "AES-ECB", "label": "AES-ECB (motifs visibles)"},
    {"step": 3, "algo": "AES-CBC", "label": "AES-CBC (modif. non détectée)"},
    {"step": 4, "algo": "AES-GCM", "label": "AES-GCM (modif. détectée)"},
    {"step": 5, "algo": "AES-GCM", "label": "ECDH X25519 + AES-GCM", "dist": "x25519",
     "note": "Clé de session = SHA-256(secret X25519), jamais vue par le serveur."},
]

ALGO_TO_MODE = {
    "Aucun": "clair", "César": "clair", "Vigenère": "clair", "XOR": "clair", "RC4": "clair",
    "DES-ECB": "ECB", "DES-CBC": "CBC", "3DES-CBC": "CBC",
    "AES-ECB": "ECB", "AES-CBC": "CBC", "AES-CTR": "CTR", "AES-GCM": "GCM",
    "ChaCha20-Poly1305": "AEAD",
}

ALLOWED_ALGOS = set(ALGO_TO_MODE)
KEY_DISTRIBUTIONS = ("broadcast", "password", "x25519")


def get_settings(db: DbSession) -> DemoSettings:
    row = db.get(DemoSettings, 1)
    if not row:
        row = DemoSettings(id=1, algo="Aucun", mode="clair",
                           key_distribution="broadcast",
                           broadcast_key_hex=secrets.token_hex(32),
                           presentation_step=0)
        db.add(row)
        db.commit()
    elif not row.broadcast_key_hex:
        row.broadcast_key_hex = secrets.token_hex(32)
        db.commit()
    return row


SAFE_ALGOS = {"AES-GCM", "ChaCha20-Poly1305"}


def settings_payload(row: DemoSettings) -> dict:
    """Réglages envoyés aux clients.

    DEMO_MODE=false : failles volontaires désactivées → pas de clé diffusée en clair
    (bascule X25519), algorithme imposé AEAD (AES-GCM) si l'algo courant est faible.
    """
    from app import config
    algo, mode, dist, key = row.algo, row.mode, row.key_distribution, row.broadcast_key_hex
    if not config.DEMO_MODE:
        if algo not in SAFE_ALGOS:
            algo, mode = "AES-GCM", "GCM"
        if dist == "broadcast":
            dist = "x25519"
        key = None
    return {
        "type": "demo.settings",
        "algo": algo,
        "mode": mode,
        "key_distribution": dist,
        "broadcast_key_hex": key,  # faille volontaire (DEMO_MODE=true uniquement)
        "presentation_step": row.presentation_step,
    }


def new_broadcast_key(db: DbSession, actor_id: int | None = None) -> DemoSettings:
    row = get_settings(db)
    row.broadcast_key_hex = secrets.token_hex(32)
    db.add(ActivityLog(actor_id=actor_id, action="demo.nouvelle_cle", detail_json="{}"))
    db.commit()
    return row


def update_settings(db: DbSession, *, algo: str | None = None,
                    key_distribution: str | None = None,
                    presentation_step: int | None = None,
                    actor_id: int | None = None) -> DemoSettings:
    row = get_settings(db)
    if algo is not None:
        if algo not in ALLOWED_ALGOS:
            raise ValueError(f"algorithme inconnu : {algo}")
        row.algo = algo
        row.mode = ALGO_TO_MODE[algo]
    if key_distribution is not None:
        if key_distribution not in KEY_DISTRIBUTIONS:
            raise ValueError("mode de distribution invalide")
        # password / x25519 acceptés dans l'UI mais non fonctionnels (étape 4)
        row.key_distribution = key_distribution
    if presentation_step is not None:
        if not (0 <= presentation_step < len(PRESENTATION)):
            raise ValueError("étape de présentation invalide")
        row.presentation_step = presentation_step
        step = PRESENTATION[presentation_step]
        row.algo = step["algo"]
        row.mode = ALGO_TO_MODE[step["algo"]]
        row.key_distribution = step.get("dist", "broadcast")
    db.add(ActivityLog(actor_id=actor_id, action="demo.reglages",
                       detail_json=f'{{"algo":"{row.algo}","dist":"{row.key_distribution}",'
                                   f'"step":{row.presentation_step}}}'))
    db.commit()
    return row


def new_des_short_key(db: DbSession, actor_id: int | None = None) -> DemoSettings:
    """Clé DES volontairement faible : 5 octets nuls + 3 aléatoires (24 bits efficaces)."""
    row = get_settings(db)
    row.broadcast_key_hex = ("00" * 5) + secrets.token_hex(3) + ("00" * 24)  # 32 octets, préfixe DES
    row.algo = "DES-CBC"
    row.mode = "CBC"
    db.add(ActivityLog(actor_id=actor_id, action="demo.cle_des_courte", detail_json="{}"))
    db.commit()
    return row
