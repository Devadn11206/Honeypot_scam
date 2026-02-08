import logging

import requests

from logger import log_summary_event

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

def _extract_suspicious_keywords(history_text: str):
    lowered = history_text.lower()
    found = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lowered:
            found.append(kw)
    return found

def _assess_sophistication(history_text: str, intelligence: dict) -> str:
    lowered = history_text.lower()
    has_link = bool(intelligence.get("phishing_urls"))
    has_payment_ids = bool(intelligence.get("bank_accounts") or intelligence.get("upi_ids") or intelligence.get("phone_numbers"))
    has_banking_terms = any(term in lowered for term in ["kyc", "ifsc", "otp", "account", "bank", "verification"])
    urgency = any(term in lowered for term in ["urgent", "immediately", "blocked", "suspended", "2 hours", "limited time"])

    if has_link and has_payment_ids and has_banking_terms:
        return "high (uses links plus banking/payment identifiers)"
    if has_payment_ids and has_banking_terms:
        return "moderate (uses banking/payment identifiers)"
    if urgency or has_banking_terms:
        return "low-to-moderate (urgency and verification cues)"
    return "low (generic pressure without specific identifiers)"

def _build_agent_notes(history_text: str, intelligence: dict, risk_analysis: dict | None) -> str:
    keywords = _extract_suspicious_keywords(history_text)
    sophistication = _assess_sophistication(history_text, intelligence)
    suspicious_phrases = []
    identifier_links = []
    if isinstance(risk_analysis, dict):
        suspicious_phrases = risk_analysis.get("suspicious_phrases") or []
        identifier_links = risk_analysis.get("identifier_links") or []

    parts = []
    if keywords:
        parts.append(f"Scammer leveraged urgency/verification cues ({', '.join(sorted(set(keywords)))}).")
    if suspicious_phrases:
        parts.append(f"Session-specific scam phrases: {', '.join(suspicious_phrases[:5])}.")
    if intelligence.get("upi_ids") or intelligence.get("bank_accounts") or intelligence.get("phone_numbers"):
        parts.append("Agent attempted to extract payment identifiers through verification-style questions.")
    if intelligence.get("phishing_urls"):
        parts.append("Scammer included a link, indicating potential phishing redirection.")
    if identifier_links:
        sample = identifier_links[:2]
        mapped = "; ".join([f"{item.get('identifier')} -> {item.get('url')}" for item in sample if isinstance(item, dict)])
        if mapped:
            parts.append(f"Identifier-link pairing observed: {mapped}.")
    parts.append(f"Sophistication assessment: {sophistication}.")
    return " ".join(parts)

def send_final_callback(session_id, history, intelligence, notes=None, risk_analysis=None):
    history_text = "\n".join(history)
    agent_notes = notes or _build_agent_notes(history_text, intelligence, risk_analysis)
    sophistication = _assess_sophistication(history_text, intelligence)
    payload = {
        "sessionId": session_id,
        "scamDetected": True,
        "totalMessagesExchanged": len(history),
        "extractedIntelligence": {
            "bankAccounts": intelligence.get("bank_accounts", []),
            "upiIds": intelligence.get("upi_ids", []),
            "phishingLinks": intelligence.get("phishing_urls", []),
            "phoneNumbers": intelligence.get("phone_numbers", []),
            "suspiciousKeywords": _extract_suspicious_keywords(history_text),
        },
        "agentNotes": agent_notes
    }

    # Always append a summary row to the CSV log
    suspicious_phrases = []
    if isinstance(risk_analysis, dict):
        suspicious_phrases = risk_analysis.get("suspicious_phrases") or []
    log_summary_event(
        session_id=session_id,
        intel=intelligence,
        suspicious_phrases=suspicious_phrases,
        sophistication=sophistication,
    )
    
    try:
        url = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
        res = requests.post(url, json=payload, timeout=10)
        logging.info(f"Callback Status: {res.status_code}")
    except Exception as e:
        logging.error(f"Callback Failed: {e}")
