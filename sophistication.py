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

    # Accept both snake_case and camelCase keys for robustness
    upi_ids = _as_list(intel.get("upi_ids") or intel.get("upiIds"))
    bank_accounts = _as_list(intel.get("bank_accounts") or intel.get("bankAccounts"))
    ifsc_codes = _as_list(intel.get("ifsc_codes") or intel.get("ifscCodes") or intel.get("ifsc_codes"))
    phone_numbers = _as_list(intel.get("phone_numbers") or intel.get("phoneNumbers"))
    phishing_urls = _as_list(intel.get("phishing_urls") or intel.get("phishingLinks") or intel.get("phishing_links"))

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

    # If multiple identifier categories are present or multiple identifiers
    # overall, treat as high sophistication — attackers are using varied data.
    if structured_or_multiple:
        level = "high"
    elif has_url and has_impersonation:
        level = "high"
    elif has_payment_ids or has_urgency or has_impersonation:
        level = "medium"
    else:
        level = "low"

    # Channel analysis: accept metadata or top-level channel keys
    metadata = intel.get("metadata") or {}
    channel = (metadata.get("channel") if isinstance(metadata, dict) else None) or intel.get("channel")
    channel_list = []
    if isinstance(channel, (list, tuple)):
        channel_list = list(channel)
    elif channel:
        channel_list = [str(channel)]

    channel_analysis = {
        "channels": channel_list,
        "cross_platform": len(set(channel_list)) > 1,
    }

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

    # Channel-based bonuses: cross-platform campaigns are higher value
    if channel_analysis.get("cross_platform"):
        score += 15
    elif channel_list:
        # Single-channel boosts: SMS tends to be higher-impact for urgent scams
        ch = channel_list[0].lower()
        if "sms" in ch:
            score += 8
        elif "email" in ch:
            score += 4
        elif "whatsapp" in ch or "wa" in ch:
            score += 6

    score = max(0, min(int(score), 100))
    return {
        "sophistication_level": level,
        "intelligence_value_score": score,
        "channel_analysis": channel_analysis,
    }
