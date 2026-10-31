#!/usr/bin/env python3
"""Point d'entrée : crée la base, sème les comptes de démo, démarre uvicorn."""
import uvicorn

from app import config
from app.database import SessionLocal, init_db
from app.seed import seed


def main():
    init_db()
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()
    print(f"→ {config.APP_NAME} sur http://{config.HOST}:{config.PORT}  (DEMO_MODE={config.DEMO_MODE})")
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=False)


if __name__ == "__main__":
    main()
