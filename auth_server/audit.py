"""
Audit logging (M13). Security-relevant events only; no tokens, passwords, or full request bodies.
Audit UI (M15): GET /audit/ui returns HTML table with optional filters.
"""
import html as html_lib
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
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


def _query_audit_logs(
    db: Session,
    *,
    limit: int = 100,
    event_type: str | None = None,
    outcome: str | None = None,
    client_id: str | None = None,
):
    """Query audit logs with optional filters. Most recent first."""
    q = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if event_type is not None and event_type != "":
        q = q.filter(AuditLog.event_type == event_type)
    if outcome is not None and outcome != "":
        q = q.filter(AuditLog.outcome == outcome)
    if client_id is not None and client_id != "":
        q = q.filter(AuditLog.client_id == client_id)
    rows = q.limit(min(limit, 500)).all()
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


@router.get("/audit")
def list_audit_logs(
    limit: int = 100,
    event_type: str | None = None,
    outcome: str | None = None,
    client_id: str | None = None,
    db: Session = Depends(get_db),
):
    """List recent audit events (lab use). No tokens or secrets. Most recent first."""
    return _query_audit_logs(
        db, limit=limit, event_type=event_type, outcome=outcome, client_id=client_id
    )


def _escape(s: str | None) -> str:
    if s is None:
        return ""
    return html_lib.escape(str(s))


@router.get("/audit/ui", response_class=HTMLResponse)
def audit_ui(
    limit: int = 100,
    event_type: str | None = None,
    outcome: str | None = None,
    client_id: str | None = None,
    db: Session = Depends(get_db),
):
    """M15: Read-only audit log viewer (HTML). Lab/dev only; do not expose in production."""
    events = _query_audit_logs(
        db, limit=limit, event_type=event_type, outcome=outcome, client_id=client_id
    )
    # Current filter values for the form (empty string = show all)
    ev = _escape(event_type) if event_type else ""
    oc = _escape(outcome) if outcome else ""
    cid = _escape(client_id) if client_id else ""
    limit_val = min(max(1, limit), 500)

    rows_html = []
    for e in events:
        ts = _escape(e.get("created_at") or "")
        et = _escape(e.get("event_type") or "")
        c = _escape(e.get("client_id") or "")
        uid = e.get("user_id")
        user_display = str(uid) if uid is not None else "anonymous"
        user_display = _escape(user_display)
        ip = _escape(e.get("ip") or "")
        out = _escape(e.get("outcome") or "")
        rows_html.append(
            f"<tr><td>{ts}</td><td>{et}</td><td>{c}</td><td>{user_display}</td><td>{ip}</td><td>{out}</td></tr>"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Audit log (lab)</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 1rem 2rem; }}
    table {{ border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.8rem; text-align: left; }}
    th {{ background: #eee; }}
    form {{ display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; }}
    label {{ display: flex; align-items: center; gap: 0.3rem; }}
    .note {{ color: #666; font-size: 0.9rem; margin-top: 1rem; }}
  </style>
</head>
<body>
  <h1>Audit log</h1>
  <form method="get" action="/audit/ui">
    <label>Limit <input type="number" name="limit" min="1" max="500" value="{limit_val}"></label>
    <label>Event type <input type="text" name="event_type" value="{ev}" placeholder="e.g. login_ok"></label>
    <label>Outcome
      <select name="outcome">
        <option value="">all</option>
        <option value="success" {"selected" if outcome == "success" else ""}>success</option>
        <option value="fail" {"selected" if outcome == "fail" else ""}>fail</option>
      </select>
    </label>
    <label>Client ID <input type="text" name="client_id" value="{cid}" placeholder="e.g. test-client"></label>
    <button type="submit">Apply</button>
  </form>
  <p class="note">Most recent first. Lab use only; do not expose in production.</p>
  <table>
    <thead><tr><th>Time (UTC)</th><th>Event</th><th>Client ID</th><th>User</th><th>IP</th><th>Outcome</th></tr></thead>
    <tbody>
      {"".join(rows_html) if rows_html else "<tr><td colspan=\"6\">No events</td></tr>"}
    </tbody>
  </table>
</body>
</html>"""
    return HTMLResponse(html_content)
