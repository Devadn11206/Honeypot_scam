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

    payment_phrases = ("send", "transfer", "pay", "remit", "invoice", "wire", "fund", "bank transfer", "new account", "swift", "beneficiary")
    if phone_numbers and any(p in lowered for p in payment_phrases):
        score += 0.2

    # If an explicit payment-related phrase appears together with an account identifier, boost score (BEC-like)
    if (bank_accounts or upi_ids) and any(p in lowered for p in payment_phrases):
        score += 0.5

    # If audit/migration/account-change context appears with a payment identifier, treat as high-risk BEC
    audit_phrases = ("audit", "migrat", "migration", "change of bank", "new bank", "account migration", "details have changed", "internal audit", "banking details", "new account", "update bank", "beneficiary change")
    if (bank_accounts or upi_ids or ifsc_codes) and any(p in lowered for p in audit_phrases):
        score += 0.6

    # If job-related context appears with a payment identifier (UPI/bank), treat as job fraud
    job_phrases = ("hiring", "job", "recruit", "recruiting", "recruitment", "vacancy", "onboarding", "interview", "employment", "employ", "position", "applicant", "freelance", "gig", "contract", "virtual assistant", "data entry", "remote work", "work from home")
    if (upi_ids or bank_accounts or ifsc_codes) and any(p in lowered for p in job_phrases):
        score += 0.5

    urgency_phrases = ("urgent", "immediately", "blocked account", "otp", "asap", "final warning", "act now", "expires soon")
    if any(p in lowered for p in urgency_phrases):
        score += 0.1

    # Phishing + payment identifier combo (broader detection)
    if phishing_urls and (upi_ids or bank_accounts):
        score += 0.3

    if phishing_urls:
        score += 0.2

    confidence_score = min(1.0, score)
    scam_detected = confidence_score >= 0.5
    return scam_detected, confidence_score
