"""
In-memory store for pending authorization flows (state -> nonce, code_verifier).
Used between /start-login and /callback. TTL to avoid unbounded growth.
"""
import time
from dataclasses import dataclass
from typing import Any

# TTL seconds for pending flow (authorization code is 1 min at AS; allow 10 min for user)
FLOW_TTL = 600


@dataclass
class PendingFlow:
    nonce: str
    code_verifier: str
    created_at: float

    def expired(self) -> bool:
        return (time.monotonic() - self.created_at) > FLOW_TTL


_pending: dict[str, PendingFlow] = {}


def store_flow(state: str, nonce: str, code_verifier: str) -> None:
    _pending[state] = PendingFlow(nonce=nonce, code_verifier=code_verifier, created_at=time.monotonic())


def get_flow(state: str) -> PendingFlow | None:
    flow = _pending.pop(state, None)
    if flow is None or flow.expired():
        return None
    return flow


def _clean_expired() -> None:
    now = time.monotonic()
    expired = [s for s, f in _pending.items() if (now - f.created_at) > FLOW_TTL]
    for s in expired:
        del _pending[s]
