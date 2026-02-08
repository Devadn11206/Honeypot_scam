from __future__ import annotations

from typing import Any, Mapping


_IMPERSONATION_KEYWORDS = (
    "bank",
    "kyc",
    "support",
    "official",
    "customer care",
    "helpline",
    "service desk",
)

_URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "blocked",
    "blocked account",
    "account blocked",
    "otp",
    "final warning",
    "last chance",
)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    return [str(v) for v in items if v is not None and str(v).strip()]


def compute_sophistication(text: str, extracted_intelligence: Mapping[str, Any]) -> dict:
    """Classify scam sophistication and rank intelligence value.

    Returns:
      {
        "sophistication_level": "low"|"medium"|"high",
        "intelligence_value_score": int (0..100)
      }

    Notes:
    - Designed to be lightweight and synchronous (safe for async endpoints).
    - Uses only simple string matching + extracted identifier counts.
    """

    lowered = (text or "").lower()
    intel = extracted_intelligence or {}

    upi_ids = _as_list(intel.get("upi_ids"))
    bank_accounts = _as_list(intel.get("bank_accounts"))
    ifsc_codes = _as_list(intel.get("ifsc_codes"))
    phone_numbers = _as_list(intel.get("phone_numbers"))
    phishing_urls = _as_list(intel.get("phishing_urls"))

    has_url = len(phishing_urls) > 0
    has_payment_ids = (len(upi_ids) > 0) or (len(bank_accounts) > 0) or (len(ifsc_codes) > 0)
    has_urgency = any(p in lowered for p in _URGENCY_PHRASES)
    has_impersonation = any(k in lowered for k in _IMPERSONATION_KEYWORDS)

    categories_present = sum(
        1
        for present in (
            bool(upi_ids),
            bool(bank_accounts),
            bool(ifsc_codes),
            bool(phone_numbers),
            bool(phishing_urls),
        )
        if present
    )
    total_identifiers = len(upi_ids) + len(bank_accounts) + len(ifsc_codes) + len(phone_numbers) + len(phishing_urls)

    structured_or_multiple = (categories_present >= 2) or (total_identifiers >= 3)

    if has_url and has_impersonation and structured_or_multiple:
        level = "high"
    elif has_payment_ids or has_urgency:
        level = "medium"
    else:
        level = "low"

    # Intelligence value score (0..100)
    # Weighted by identifier type and quantity; capped to 100.
    score = 0
    score += min(len(upi_ids), 3) * 15
    score += min(len(bank_accounts), 2) * 20
    score += min(len(ifsc_codes), 2) * 20
    score += min(len(phone_numbers), 3) * 10
    score += min(len(phishing_urls), 2) * 25

    # Bonus for banking + phishing.
    if (bank_accounts or ifsc_codes):
        score += 10
    if phishing_urls:
        score += 15

    # Optional campaign bonus (backward compatible: only applied if caller already has campaign detection).
    campaign_detected = bool(intel.get("campaign_detected")) or bool(intel.get("campaign_id"))
    if campaign_detected:
        score += 10

    score = max(0, min(int(score), 100))

    return {
        "sophistication_level": level,
        "intelligence_value_score": score,
    }
