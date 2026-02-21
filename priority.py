from __future__ import annotations

from typing import Any

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "verification",
    "account blocked",
    "account suspended",
    "kyc",
    "click",
    "link",
    "payment",
    "upi",
    "bank",
    "refund",
]


def extract_suspicious_keywords(history_text: str) -> list[str]:
    lowered = (history_text or "").lower()
    found: list[str] = []
    seen = set()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered and kw not in seen:
            seen.add(kw)
            found.append(kw)
    return found


def compute_priority(extracted_intelligence: dict) -> str:
    intel = extracted_intelligence or {}

    has_bank = bool(intel.get("bank_accounts"))
    has_phishing = bool(intel.get("phishing_urls"))
    if has_bank or has_phishing:
        return "critical"

    suspicious_keywords = intel.get("suspicious_keywords") or []
    has_suspicious_keywords = bool(suspicious_keywords)

    has_phone = bool(intel.get("phone_numbers"))
    if has_phone and has_suspicious_keywords:
        return "high"

    if has_suspicious_keywords:
        return "medium"

    return "low"


def generate_investigator_summary(
    session_id: str,
    extracted_intelligence: dict,
    priority_level: str,
    campaign_info: dict,
) -> dict:
    # Extract channel metadata if present
    metadata = extracted_intelligence.get("metadata") if isinstance(extracted_intelligence, dict) else {}
    channel = (metadata.get("channel") if isinstance(metadata, dict) else None) or extracted_intelligence.get("channel")

    # Map channel to recommended action
    recommended_action = "Block associated accounts and telecom identifiers"
    if channel:
        ch = str(channel).lower()
        if "sms" in ch:
            recommended_action = "Report SMS sender to telecom provider; block number; escalate to regulator."
        elif "whatsapp" in ch or "wa" in ch:
            recommended_action = "Report profile to WhatsApp and block; collect account flags for platform takedown."
        elif "email" in ch:
            recommended_action = "Report sender to email provider and mark for spam/phishing; collect headers."
        elif "social" in ch or "telegram" in ch:
            recommended_action = "Report account to platform trust & safety; block and collect profile links."

    return {
        "session_id": session_id,
        "scam_type": "financial fraud",
        "primary_identifiers": extracted_intelligence,
        "priority_level": priority_level,
        "campaign_detected": bool(campaign_info.get("campaign_detected")),
        "campaign_strength": int(campaign_info.get("campaign_strength", 1) or 1),
        "channel": channel,
        "recommended_action": recommended_action,
    }
