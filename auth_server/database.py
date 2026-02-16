"""
Database engine and session for auth server. SQLite per PROJECT_CONTEXT.
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_server.config import DATABASE_URL
from auth_server.models import Base

# SQLite: in-memory needs StaticPool so all connections share the same DB (for tests)
# File-based SQLite needs check_same_thread=False for FastAPI
if DATABASE_URL.startswith("sqlite:///:memory:"):
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
    engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Create all tables and run simple migrations (e.g. add nonce column for M4)."""
    Base.metadata.create_all(bind=engine)
    if "sqlite" in DATABASE_URL:
        with engine.connect() as conn:
            for col, typ, table in [
                ("nonce", "VARCHAR(255)", "authorization_codes"),
                ("name", "VARCHAR(255)", "users"),
                ("email", "VARCHAR(255)", "users"),
                ("client_secret_hash", "VARCHAR(255)", "clients"),
            ]:
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {typ}"))
                    conn.commit()
                except Exception:
                    conn.rollback()
                    # Column may already exist
                    pass


def get_db():
    """Dependency: yield a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
