from __future__ import annotations

from typing import Tuple


def compute_scam_score(text: str, extracted_intelligence: dict) -> Tuple[bool, float]:
    """Compute a lightweight heuristic scam score.

    Scoring rules (additive; clamped to 1.0):
    - Presence of UPI IDs, bank accounts, or IFSC codes -> +0.5
    - Phone number + payment-related phrase ("send", "transfer", "pay") -> +0.2
    - Urgency phrases ("urgent", "immediately", "blocked account", "otp") -> +0.1
    - Phishing URL detected -> +0.2

    scam_detected is True when confidence_score >= 0.5.
    """

    lowered = (text or "").lower()
    intel = extracted_intelligence or {}

    upi_ids = intel.get("upi_ids") or []
    bank_accounts = intel.get("bank_accounts") or []
    ifsc_codes = intel.get("ifsc_codes") or []
    phone_numbers = intel.get("phone_numbers") or []
    phishing_urls = intel.get("phishing_urls") or []

    score = 0.0

    if upi_ids or bank_accounts or ifsc_codes:
        score += 0.5

    payment_phrases = ("send", "transfer", "pay")
    if phone_numbers and any(p in lowered for p in payment_phrases):
        score += 0.2

    urgency_phrases = ("urgent", "immediately", "blocked account", "otp")
    if any(p in lowered for p in urgency_phrases):
        score += 0.1

    if phishing_urls:
        score += 0.2

    confidence_score = min(1.0, score)
    scam_detected = confidence_score >= 0.5
    return scam_detected, confidence_score
