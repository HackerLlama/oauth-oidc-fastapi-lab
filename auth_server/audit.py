"""
Audit logging (M13). Security-relevant events only; no tokens, passwords, or full request bodies.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from auth_server.database import get_db
from auth_server.models import AuditLog

EVENT_LOGIN_OK = "login_ok"
EVENT_LOGIN_FAIL = "login_fail"
EVENT_CONSENT_ALLOW = "consent_allow"
EVENT_CONSENT_DENY = "consent_deny"
EVENT_CODE_ISSUED = "code_issued"
EVENT_TOKEN_ISSUED = "token_issued"
EVENT_TOKEN_REFRESHED = "token_refreshed"
EVENT_TOKEN_REVOKED = "token_revoked"
EVENT_INTROSPECT = "introspect"

OUTCOME_SUCCESS = "success"
OUTCOME_FAIL = "fail"


def get_client_ip(request: Request | None) -> str | None:
    """Client IP if available (e.g. request.client.host). No forwarding headers for lab."""
    if request is None or request.client is None:
        return None
    return getattr(request.client, "host", None)


def log_audit(
    db: Session,
    event_type: str,
    *,
    client_id: str | None = None,
    user_id: int | None = None,
    ip: str | None = None,
    outcome: str = OUTCOME_SUCCESS,
) -> None:
    """Append one audit record. Never log tokens or passwords."""
    db.add(
        AuditLog(
            event_type=event_type,
            client_id=client_id,
            user_id=user_id,
            ip=ip,
            outcome=outcome,
        )
    )
    db.commit()


router = APIRouter(tags=["audit"])


@router.get("/audit")
def list_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """List recent audit events (lab use). No tokens or secrets. Most recent first."""
    rows = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [
        {
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "event_type": r.event_type,
            "client_id": r.client_id,
            "user_id": r.user_id,
            "ip": r.ip,
            "outcome": r.outcome,
        }
        for r in rows
    ]
