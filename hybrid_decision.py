from __future__ import annotations

from typing import Any, Mapping, Tuple


_EVIDENCE_KEYS = (
    "upi_ids",
    "phishing_urls",
    "phone_numbers",
    "bank_accounts",
    "ifsc_codes",
)


def has_intelligence_evidence(extracted_intelligence: Mapping[str, Any] | None) -> bool:
    """Return True if any high-signal scam identifiers were extracted."""
    intel = extracted_intelligence or {}
    for key in _EVIDENCE_KEYS:
        value = intel.get(key)
        if isinstance(value, (list, tuple, set)) and len(value) > 0:
            return True
        if isinstance(value, str) and value.strip():
            return True
    return False


def compute_final_risk(
    model_detected: bool,
    confidence_score: float,
    extracted_intelligence: Mapping[str, Any] | None,
    *,
    evidence_min_confidence: float = 0.75,
) -> Tuple[bool, float]:
    """Hybrid decision logic.

    Rules:
    - If any UPI ID, phishing URL, phone number, bank account, or IFSC code is detected,
      force final_detected=True and final_confidence=max(model_confidence, 0.75)
    - Otherwise keep the model prediction.

    Confidence is clamped to [0, 1].
    """

    try:
        model_confidence = float(confidence_score)
    except Exception:
        model_confidence = 0.0

    model_confidence = max(0.0, min(model_confidence, 1.0))

    if has_intelligence_evidence(extracted_intelligence):
        final_detected = True
        final_confidence = max(model_confidence, float(evidence_min_confidence))
    else:
        final_detected = bool(model_detected)
        final_confidence = model_confidence

    final_confidence = max(0.0, min(final_confidence, 1.0))
    return final_detected, final_confidence
