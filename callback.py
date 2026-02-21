import logging

import requests

from logger import log_summary_event
from sophistication import compute_sophistication

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
    # Use the more detailed sophistication computation where possible
    try:
        sophistication_result = compute_sophistication(history_text, intelligence)
        sophistication = sophistication_result.get("sophistication_level")
        intel_score = sophistication_result.get("intelligence_value_score")
    except Exception:
        sophistication = _assess_sophistication(history_text, intelligence)
        intel_score = None

    suspicious_phrases = []
    identifier_links = []
    if isinstance(risk_analysis, dict):
        suspicious_phrases = risk_analysis.get("suspicious_phrases") or []
        identifier_links = risk_analysis.get("identifier_links") or []

    parts = []
    if keywords:
        parts.append(f"Scammer used urgency/verification cues: {', '.join(sorted(set(keywords)))}.")
    if suspicious_phrases:
        parts.append(f"Session-specific suspicious phrases: {', '.join(suspicious_phrases[:5])}.")

    # Provide detailed identifier summary (types, counts, and examples)
    examples: list[str] = []
    def _take_examples(key: str, label: str, limit: int = 2):
        vals = intelligence.get(key) or intelligence.get(label.lower().replace(' ', '_')) or []
        vals = vals or []
        vals = [str(v) for v in vals if v]
        if not vals:
            return None
        return (label, len(vals), vals[:limit])

    id_summary = []
    for key, label in (("upi_ids", "UPI IDs"), ("bank_accounts", "Bank accounts"), ("phone_numbers", "Phone numbers"), ("phishing_urls", "Links"), ("ifsc_codes", "IFSC codes")):
        info = _take_examples(key, label)
        if info:
            lbl, cnt, ex = info
            id_summary.append(f"{lbl}: {cnt} (e.g. {', '.join(ex)})")

    if id_summary:
        parts.append("Captured identifiers: " + "; ".join(id_summary) + ".")
    else:
        parts.append("No actionable identifiers captured yet.")

    if identifier_links:
        sample = identifier_links[:3]
        mapped = "; ".join([f"{item.get('identifier')} -> {item.get('url')}" for item in sample if isinstance(item, dict)])
        if mapped:
            parts.append(f"Identifier-link pairings observed: {mapped}.")

    # Add sophistication summary with optional score
    score_text = f" (score {intel_score})" if intel_score is not None else ""
    parts.append(f"Sophistication assessment: {sophistication}{score_text}.")

    # Suggest next investigative action succinctly
    if intelligence.get("upi_ids") or intelligence.get("bank_accounts"):
        parts.append("Next: ask for beneficiary name and official receipt/reference to validate payment details.")
    elif intelligence.get("phishing_urls"):
        parts.append("Next: ask for official domain and why the link is required; request a reference number.")
    else:
        parts.append("Next: continue polite verification questions to elicit identifiers.")

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
