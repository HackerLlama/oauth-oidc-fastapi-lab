"""
SQLAlchemy models for Authorization Server (PROJECT_CONTEXT: Users, OAuth Clients, Authorization Codes).
"""
import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    # JSON array of allowed redirect URIs; exact match required
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)  # stored as JSON string
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)

    def get_redirect_uris_list(self) -> list[str]:
        return json.loads(self.redirect_uris)

    def redirect_uri_allowed(self, uri: str) -> bool:
        return uri in self.get_redirect_uris_list()


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # space-separated
    code_challenge: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)  # for ID token when openid scope
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)

    user: Mapped["User"] = relationship("User", backref="authorization_codes")
