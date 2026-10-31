"""Moteur SQLAlchemy et fabrique de sessions."""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app import config

engine = create_engine(config.DATABASE_URL, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from app import models  # noqa: F401  (enregistre les tables)
    Base.metadata.create_all(engine)
    _migrate()


def _migrate():
    """Migrations légères SQLite (ajout de colonnes sur une base existante)."""
    from sqlalchemy import text
    with engine.begin() as conn:
        cols = {r[1] for r in conn.execute(text("PRAGMA table_info(messages)"))}
        for col in ("key_dist", "key_fp"):
            if col not in cols:
                conn.execute(text(f"ALTER TABLE messages ADD COLUMN {col} VARCHAR(16)"))
