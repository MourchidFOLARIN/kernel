"""Configuration centrale, surchargeable par variables d'environnement."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

APP_NAME = os.getenv("KERNEL_APP_NAME", "Kernel")
# DEMO_MODE active plus tard la page Ève, le panneau Coulisses et les failles volontaires.
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("1", "true", "yes", "oui")
# Clé de signature des cookies. À fixer en variable d'environnement pour garder les sessions entre redémarrages.
_secret_file = BASE_DIR / ".secret_key"
if os.getenv("SECRET_KEY"):
    SECRET_KEY = os.environ["SECRET_KEY"]
else:
    if not _secret_file.exists():
        _secret_file.write_text(secrets.token_hex(32))
    SECRET_KEY = _secret_file.read_text().strip()

DATABASE_PATH = Path(os.getenv("KERNEL_DB", str(BASE_DIR / "kernel.db")))
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

HOST = os.getenv("KERNEL_HOST", "0.0.0.0")
PORT = int(os.getenv("KERNEL_PORT", "3000"))

SESSION_COOKIE = "kernel_session"
SESSION_DAYS = 7
# Limitation des tentatives de connexion : N échecs max par fenêtre (secondes), par IP+pseudo.
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
RESET_CODE_MINUTES = 15

DOMAINS = {
    "dev": "Développement",
    "cyber": "Cybersécurité",
    "data": "Data",
    "ia": "IA",
    "devops": "DevOps",
    "autre": "Autre",
}
