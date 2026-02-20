from __future__ import annotations

import threading
from collections import Counter
from typing import Any, Iterable

_LOCK = threading.Lock()
_COUNTER: Counter[str] = Counter()

_TRACK_KEYS = (
    "bank_accounts",
    "upi_ids",
    "phone_numbers",
    "phishing_urls",
)


def _as_iterable(value: Any) -> Iterable[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _identifier_key(field: str, raw_value: Any) -> str | None:
    text = str(raw_value).strip()
    if not text:
        return None

    # Prefix by field to avoid accidental cross-type collisions.
    # Normalize case for case-insensitive identifiers like URLs/UPIs.
    if field in {"upi_ids", "phishing_urls"}:
        text = text.lower()

    return f"{field}:{text}"


def detect_campaign(extracted_intelligence: dict) -> dict:
    """Track identifier occurrences globally and detect campaigns.

    Campaign rule:
    - Maintain a global counter (thread-safe)
    - If any identifier appears >= 3 times: campaign_detected=True, campaign_strength=max occurrence
    - Else: campaign_detected=False, campaign_strength=1
    """

    intel = extracted_intelligence or {}

    keys_to_increment: list[str] = []
    for field in _TRACK_KEYS:
        for item in _as_iterable(intel.get(field)):
            key = _identifier_key(field, item)
            if key:
                keys_to_increment.append(key)

    if not keys_to_increment:
        return {"campaign_detected": False, "campaign_strength": 1}

    with _LOCK:
        for key in keys_to_increment:
            _COUNTER[key] += 1

        max_count = max(_COUNTER.get(key, 0) for key in keys_to_increment)

    if max_count >= 3:
        return {"campaign_detected": True, "campaign_strength": int(max_count)}

    return {"campaign_detected": False, "campaign_strength": 1}
