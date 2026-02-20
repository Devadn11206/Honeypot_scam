from collections import defaultdict
from threading import Lock
import time

from config import MAX_HISTORY
from schemas import MessageContent

_lock = Lock()

conversations = defaultdict(lambda: {
    "history": [],
    "start_time": time.monotonic(),
    "persona_facts": [],
    "extracted": {
        "bank_accounts": [],
        "upi_ids": [],
        "phishing_urls": [],
        "ifsc_codes": [],
        "wallet_addresses": []
    }
})

def add_message(conversation_id: str, message: MessageContent) -> dict:
    with _lock:
        convo = conversations[conversation_id]
        convo["history"].append(message)

        if MAX_HISTORY and len(convo["history"]) > MAX_HISTORY:
            convo["history"] = convo["history"][-MAX_HISTORY:]

        return convo

def get_history(conversation_id: str) -> list:
    with _lock:
        return list(conversations[conversation_id]["history"])

def get_start_time(conversation_id: str) -> float:
    with _lock:
        return conversations[conversation_id]["start_time"]

def update_persona_facts(conversation_id: str, facts: list) -> list:
    with _lock:
        convo = conversations[conversation_id]
        existing = convo.get("persona_facts", [])
        seen = {str(f).lower() for f in existing}
        for fact in facts:
            key = str(fact).lower()
            if key and key not in seen:
                existing.append(fact)
                seen.add(key)
        convo["persona_facts"] = existing
        return list(existing)

def get_persona_facts(conversation_id: str) -> list:
    with _lock:
        return list(conversations[conversation_id].get("persona_facts", []))


def get_conversation_snapshot(conversation_id: str) -> dict | None:
    """Return a snapshot of a conversation without creating a new entry."""
    with _lock:
        if conversation_id not in conversations:
            return None
        convo = conversations[conversation_id]
        return {
            "history": list(convo.get("history") or []),
            "start_time": float(convo.get("start_time") or 0.0),
            "persona_facts": list(convo.get("persona_facts") or []),
            # Include any extra flags if present (e.g., callback_sent)
            **{k: v for k, v in convo.items() if k not in {"history", "start_time", "persona_facts"}},
        }
