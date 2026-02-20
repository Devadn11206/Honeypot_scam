from __future__ import annotations

from typing import Any, Dict, Optional, TypedDict

from honeypot_core import generate_final_output
from memory import get_conversation_snapshot
from redis_store import get_history


class SessionSnapshot(TypedDict, total=False):
    history: list
    start_time: float
    persona_facts: list


def get_session_data(session_id: str) -> Optional[SessionSnapshot]:
    """Retrieve stored session state by sessionId.

    Assumes session data is stored in the in-memory dictionary keyed by sessionId.
    Returns a snapshot (copy) or None if not found.
    """

    snapshot = get_conversation_snapshot(session_id)
    if snapshot:
        return snapshot

    # Fallback: if the session was only stored in Redis, reconstruct history.
    history = get_history(session_id)
    if not history:
        return None
    return {
        "history": list(history),
        "start_time": 0.0,
        "persona_facts": [],
    }


def generate_final_output_json(session_id: str, session_data: SessionSnapshot) -> Dict[str, Any]:
    """Generate the structured final output (debug-only) for a stored session."""

    history_items = list(session_data.get("history") or [])
    return generate_final_output(session_id=session_id, history_items=history_items)
