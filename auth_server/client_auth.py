"""
Client authentication for confidential clients (M9). RFC 6749 §3.2.1.
Credentials via Authorization: Basic base64(client_id:client_secret) or client_id + client_secret in form.
"""
import base64
import logging

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from auth_server.models import Client
from auth_server.seed import verify_password

logger = logging.getLogger(__name__)


def _parse_basic(header_value: str) -> tuple[str, str] | None:
    """Parse 'Basic <base64(client_id:client_secret)>'. Returns (client_id, client_secret) or None."""
    if not header_value or not header_value.strip().lower().startswith("basic "):
        return None
    try:
        encoded = header_value.strip()[6:].strip()
        decoded = base64.b64decode(encoded).decode("utf-8")
        if ":" not in decoded:
            return None
        client_id, _, client_secret = decoded.partition(":")
        return (client_id.strip(), client_secret)
    except Exception:
        return None


def verify_client_credentials(db: Session, client_id: str, client_secret: str | None) -> Client | None:
    """
    Load client by client_id; if confidential, verify client_secret against stored hash.
    Returns Client if valid, None otherwise.
    """
    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client:
        return None
    if not client.is_confidential:
        return client
    if not client_secret:
        return None
    if not verify_password(client_secret, client.client_secret_hash):
        return None
    return client


def get_client_credentials_from_request(
    request: Request,
    client_id_form: str | None,
    client_secret_form: str | None,
) -> tuple[str | None, str | None]:
    """
    Get (client_id, client_secret) from Authorization Basic or from form.
    Form takes precedence if both present (per some implementations).
    """
    auth_header = request.headers.get("Authorization")
    basic = _parse_basic(auth_header) if auth_header else None
    if client_id_form and client_secret_form is not None:
        return (client_id_form.strip(), client_secret_form)
    if basic:
        return basic
    if client_id_form:
        return (client_id_form.strip(), client_secret_form)
    return (None, None)


def require_client_auth(
    db: Session,
    request: Request,
    client_id_form: str | None,
    client_secret_form: str | None,
) -> Client:
    """
    Resolve and authenticate client. If client_id is missing or client is confidential
    and credentials are wrong, raise 401 invalid_client. Returns Client.
    """
    client_id, client_secret = get_client_credentials_from_request(
        request, client_id_form, client_secret_form
    )
    if not client_id:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "client_id is required"},
        )
    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_client", "error_description": "Unknown client"},
        )
    if client.is_confidential:
        if not verify_client_credentials(db, client_id, client_secret):
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
            )
    return client
