from __future__ import annotations

import logging
import os
import random
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from groq import Groq

from config import GROQ_API_KEY, GROQ_MODEL, MAX_CONTEXT_CHARS
from extract_intel import extract_intelligence
from schemas import MessageContent

logger = logging.getLogger(__name__)

# Keep end-to-end latency under 5 seconds by default.
DEFAULT_LLM_TIMEOUT_SECONDS = float(os.getenv("AGENT_TIMEOUT_SECONDS", "4.5"))


def _dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        v2 = (v or "").strip()
        if not v2:
            continue
        if v2 in seen:
            continue
        seen.add(v2)
        out.append(v2)
    return out


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_message_like(raw: Any, *, fallback_sender: str = "user") -> MessageContent:
    if isinstance(raw, MessageContent):
        return raw
    if isinstance(raw, dict):
        sender = str(raw.get("sender") or fallback_sender)
        text = raw.get("text") or raw.get("message") or raw.get("content") or ""
        timestamp = _safe_int(raw.get("timestamp"), 0)
        return MessageContent(sender=sender, text=str(text or ""), timestamp=int(timestamp))
    if isinstance(raw, str):
        return MessageContent(sender=fallback_sender, text=raw, timestamp=0)
    return MessageContent(sender=fallback_sender, text=str(raw or ""), timestamp=0)


def _history_scammer_text(history_items: Sequence[MessageContent]) -> str:
    parts: list[str] = []
    for m in history_items:
        if not isinstance(m, MessageContent):
            m = _coerce_message_like(m)
        sender = (getattr(m, "sender", "") or "").strip().lower()
        if sender == "honeypot":
            continue
        text = getattr(m, "text", "") or ""
        if text.strip():
            parts.append(text.strip())
    return "\n".join(parts)


def _history_lines(history_items: Sequence[MessageContent]) -> list[str]:
    lines: list[str] = []
    for m in history_items:
        if not isinstance(m, MessageContent):
            m = _coerce_message_like(m)
        sender = (getattr(m, "sender", "") or "").strip()
        text = getattr(m, "text", "") or ""
        if sender:
            lines.append(f"{sender}: {text}")
        else:
            lines.append(text)
    return lines


def _engagement_duration_seconds(history_items: Sequence[MessageContent]) -> int:
    timestamps: list[int] = []
    for m in history_items:
        if not isinstance(m, MessageContent):
            m = _coerce_message_like(m)
        ts = _safe_int(getattr(m, "timestamp", 0), 0)
        if ts > 0:
            timestamps.append(ts)

    if not timestamps:
        return 0

    start_ts = min(timestamps)
    end_ts = max(timestamps)
    if end_ts < start_ts:
        return 0
    return max(0, int((end_ts - start_ts) / 1000))


_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def _extract_domains(urls: Sequence[str]) -> list[str]:
    domains: list[str] = []
    for url in urls:
        u = (url or "").strip()
        if not u:
            continue
        # naive, fast parse: scheme://domain/... (no heavy deps)
        m = re.match(r"^https?://([^/]+)", u, flags=re.IGNORECASE)
        if not m:
            continue
        domains.append(m.group(1).lower())
    return domains


@dataclass(frozen=True)
class ScamSignals:
    scamDetected: bool
    score: float
    confidenceLevel: float
    triggers: list[str]


def normalize_text(text: str) -> str:
    normalized = (text or "").lower()
    normalized = normalized.replace(" hxxps", " https").replace(" hxxp", " http")
    normalized = re.sub(r"\bat\b", "@", normalized)
    normalized = re.sub(r"\bdot\b", ".", normalized)
    normalized = re.sub(r"h\s*[-._]*t\s*[-._]*t\s*[-._]*p\s*s?", "https", normalized)
    normalized = re.sub(r"https?\s*(\[\s*:\s*\]|:\s*)\s*(slash\s*slash|/\s*/)", "https://", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def detect_behavioral_signals(text: str, *, extracted: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized = normalize_text(text)
    extracted = extracted or {}

    extracted_upis = list(extracted.get("upiIds") or extracted.get("upi_ids") or [])
    extracted_accounts = list(extracted.get("bankAccounts") or extracted.get("bank_accounts") or [])

    upi_matches = re.findall(r"\b[a-z0-9._-]{2,}@[a-z0-9._-]{2,}\b", normalized)
    account_matches = []
    for digits in re.findall(r"\b\d{9,18}\b", normalized):
        if len(digits) == 10 and digits[:1] in {"6", "7", "8", "9"}:
            continue
        if len(digits) == 12 and digits.startswith("91") and digits[2:3] in {"6", "7", "8", "9"}:
            continue
        account_matches.append(digits)

    payment_identifier_present = bool(extracted_upis or extracted_accounts or upi_matches or account_matches)

    financial_action = bool(
        re.search(
            r"\b(?:transfer|transfer\s+(?:funds|money)|send\s+money|remit|pay(?:\s+now)?|payment|invoice|invoices|verification\s+fee|confirm\s+account|beneficiary|validate\s+payment|deposit|transaction|settle(?:ment)?|bank(?:ing)?\s*details|verify\s+payment\s+destination|wire(?:\s+transfer)?|fund|bank\s+transfer|new\s+(?:account|bank)|swift|account\s+creation)\b",
            normalized,
        )
    )

    authority_claim = bool(
        re.search(
            r"\b(i\s*am\s*from|this\s+is\s+from|calling\s+from|technical\s+desk|tech\s+support|customer\s+support|fraud\s+department|security\s+team|compliance\s+department|help\s*desk)\b",
            normalized,
        )
    )
    org_reference = bool(
        re.search(
            r"\b(bank|rbi|police|telecom|government|income\s*tax|department|support|security|team|amazon|flipkart|sbi|hdfc|icici|axis|airtel|jio|vi)\b",
            normalized,
        )
    )

    urls = _URL_RE.findall(normalized)
    domains = _extract_domains(urls)
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rb.gy",
        "rebrand.ly", "ow.ly", "cutt.ly", "shorturl.at",
    }
    legit_allow = {"amazon.in", "flipkart.com", "amazon.com", "flipkart.in"}
    has_short = any(any(d == s or d.endswith("." + s) for s in shorteners) for d in domains)
    has_unknown = any(
        d and (d not in legit_allow) and not any(d.endswith("." + a) for a in legit_allow)
        for d in domains
    )

    obfuscated_url = bool(
        re.search(r"\b(hxxp|h\s*[-._]*t\s*[-._]*t\s*[-._]*p\s*s?)\b", normalized)
        or re.search(r"\b(bit\s*\[?\.?\]?\s*ly|tinyurl\s*\[?\.?\]?\s*com|t\s*\[?\.?\]?\s*co)\b", normalized)
        or re.search(r"\bhttps?\b\s*(colon|:)\s*(slash\s*slash|//)", normalized)
    )

    signals: dict[str, bool] = {
        "urgency": bool(re.search(r"\b(urgent|immediately|act\s+now|right\s+now|asap|final\s+warning|last\s+chance|today\s+only|expires\s+soon|within\s+\d+\s*(minutes|hours))\b", normalized)),
        "otp_request": bool(re.search(r"\b(otp|one\s*time\s*password|pin|verification\s*code|security\s*code)\b", normalized)),
        "financial_info_request": bool(re.search(r"\b(cvv|card\s*number|debit\s*card|credit\s*card|account\s*number|bank\s*account|net\s*banking|ifsc)\b", normalized)),
        "direct_payment_request": bool(financial_action and payment_identifier_present),
        "fee_for_opportunity": bool(re.search(r"\b(job\s*fee|loan\s*fee|processing\s*fee|registration\s*fee|activation\s*fee|advance\s*fee|security\s*deposit)\b", normalized)),
        "identity_harvesting": bool(re.search(r"\b(confirm|verify|update|share|submit)\b.{0,40}\b(email|phone|mobile|password|username|aadhaar|pan|dob|birth\s*date|address)\b", normalized)),
        "unrealistic_reward": bool(re.search(r"\b(lottery|jackpot|guaranteed\s*returns?|double\s*your\s*money|crypto\s*doubling|assured\s*profit|risk\s*free\s*profit|winner|won\s*prize|free\s*money)\b", normalized)),
        "impersonation": bool(authority_claim and org_reference),
        "account_change_scam": bool(
            re.search(
                r"\b(details\s+(?:have\s+)?changed|change\s+of\s+bank\s+details|new\s+bank\s+details|new\s+account|update\s+payment\s+info|update\s+bank|remit(?:\s+to)?|pending\s+invoices?|invoice|invoices|internal\s+audit|account[-\s]*migration|migrat(?:ion|ed)|wireframe|beneficiary\s+change|banking\s+(?:update|change))\b",
                normalized,
            )
        ),
        "threat": bool(re.search(r"\b(legal\s*action|arrest|penalty|fine|court|fir|warrant|account\s*will\s*be\s*blocked|service\s*will\s*be\s*terminated)\b", normalized)),
        "suspicious_link": bool(obfuscated_url or has_short or has_unknown),
        "emotional_manipulation": bool(re.search(r"\b(accident|hospital|family\s*emergency|mother\s*is\s*sick|father\s*is\s*sick|help\s*me\s*urgently|medical\s*emergency)\b", normalized)),
        "secrecy_instruction": bool(re.search(r"\b(don['’]?t\s*tell\s*anyone|keep\s*this\s*secret|confidential|private\s*only|do\s*not\s*inform|bypass\s*official\s*channel|avoid\s*bank\s*support)\b", normalized)),
        "job_related": bool(re.search(r"\b(job|hiring|recruit(?:ing|ment)?|interview|vacancy|employ(?:ment|ee)?|onboarding|work\s+from\s+home|part\s*time\s*job|position|applicant|freelance|gig|contract(?:or)?|virtual\s+(?:assistant|job)|data\s+entry|remote\s+work|work\s+at\s+home)\b", normalized)),
        "financial_action": bool(financial_action),
        "payment_identifier_present": bool(payment_identifier_present),
    }

    return {
        "normalized_text": normalized,
        "signals": signals,
        "metadata": {
            "domains": domains,
            "has_short": bool(has_short),
            "has_unknown": bool(has_unknown),
            "obfuscated_url": bool(obfuscated_url),
        },
    }


def compute_scam_score(behavior: dict[str, Any]) -> dict[str, Any]:
    signals: dict[str, bool] = behavior.get("signals") or {}

    weights: dict[str, float] = {
        "urgency": 0.2,
        "otp_request": 0.3,
        "financial_info_request": 0.3,
        "direct_payment_request": 0.4,
        "fee_for_opportunity": 0.3,
        "identity_harvesting": 0.3,
        "unrealistic_reward": 0.3,
        "impersonation": 0.3,
        "threat": 0.2,
        "suspicious_link": 0.2,
        "emotional_manipulation": 0.2,
        "secrecy_instruction": 0.2,
    }

    score = 0.0
    active_signals: list[str] = []
    for name, weight in weights.items():
        if signals.get(name):
            score += weight
            active_signals.append(name)

    combo_triggers: list[str] = []
    if signals.get("impersonation") and signals.get("otp_request"):
        score += 0.2
        combo_triggers.append("combo_impersonation_otp")
    if signals.get("impersonation") and signals.get("threat"):
        score += 0.2
        combo_triggers.append("combo_impersonation_threat")
    if signals.get("financial_action") and signals.get("payment_identifier_present"):
        score += 0.4
        combo_triggers.append("combo_financial_action_payment_identifier")
    # High-risk: account migration / change combined with a payment identifier (BEC style)
    if signals.get("account_change_scam") and signals.get("payment_identifier_present"):
        score += 0.6
        combo_triggers.append("combo_account_migration_fraud")
    if signals.get("job_related") and signals.get("fee_for_opportunity"):
        score += 0.4
        combo_triggers.append("combo_job_fee")
    # Job fraud: job-related + payment identifier (UPI/bank) = high-risk employment scam
    if signals.get("job_related") and signals.get("payment_identifier_present"):
        score += 0.5
        combo_triggers.append("combo_job_fraud_payment")
    if signals.get("unrealistic_reward") and (signals.get("direct_payment_request") or signals.get("financial_action")):
        score += 0.3
        combo_triggers.append("combo_reward_payment")
    # Broader combo triggers for additional detection patterns
    # Obfuscated link + payment identifier + urgency = phishing scam
    if signals.get("suspicious_link") and signals.get("payment_identifier_present") and signals.get("urgency"):
        score += 0.5
        combo_triggers.append("combo_phishing_payment_urgency")
    # Obfuscated link + financial action = phishing with payment request
    if signals.get("suspicious_link") and signals.get("financial_action"):
        score += 0.4
        combo_triggers.append("combo_phishing_payment")
    # Urgency + fee request = urgent scam fee
    if signals.get("urgency") and signals.get("fee_for_opportunity"):
        score += 0.3
        combo_triggers.append("combo_urgent_fee")
    # Threat + payment identifier = coercion scam
    if signals.get("threat") and signals.get("payment_identifier_present"):
        score += 0.4
        combo_triggers.append("combo_threat_payment")
    # Fee + suspicious link = fraudulent offer link
    if signals.get("fee_for_opportunity") and signals.get("suspicious_link"):
        score += 0.3
        combo_triggers.append("combo_fee_phishing")
    # Suspicious link + authority claim = phishing impersonation scam
    normalized_text = behavior.get("normalized_text", "")
    if signals.get("suspicious_link") and re.search(
        r"\b(i\s*am|this\s+is|calling|message|am\s+from|here\s+writing|am\s+a|works\s+at|employed\s+by)\b.{0,100}\b(from|with|at|representing)\b",
        normalized_text,
    ):
        score += 0.4
        combo_triggers.append("combo_suspicious_link_authority")

    # Anti false positives:
    weak_signals = {"suspicious_link", "urgency", "emotional_manipulation", "secrecy_instruction"}
    high_risk = any(
        signals.get(k)
        for k in [
            "otp_request",
            "financial_info_request",
            "direct_payment_request",
            "fee_for_opportunity",
            "identity_harvesting",
            "unrealistic_reward",
            "impersonation",
        ]
    )
    coercion = any(signals.get(k) for k in ["urgency", "threat", "secrecy_instruction", "emotional_manipulation"])
    job_fraud = signals.get("job_related") and signals.get("payment_identifier_present")
    bec_risk = signals.get("account_change_scam") and signals.get("payment_identifier_present")
    
    # Check for high-risk combos that override weak-signal rejection
    has_critical_combo = any(t.startswith("combo_") for t in combo_triggers if t in ["combo_account_migration_fraud", "combo_job_fraud_payment", "combo_suspicious_link_authority"])

    if len(active_signals) == 1 and active_signals[0] in weak_signals and not has_critical_combo:
        scam_detected = False
    elif not high_risk and not coercion and not job_fraud and not bec_risk and not has_critical_combo:
        scam_detected = False
    else:
        scam_detected = score >= 0.4

    score = float(max(0.0, min(3.0, score)))

    # Count high-risk signals to gate "critical" confidence values >0.95.
    high_risk_keys = [
        "otp_request",
        "financial_info_request",
        "direct_payment_request",
        "fee_for_opportunity",
        "identity_harvesting",
        "unrealistic_reward",
        "impersonation",
    ]
    high_risk_count = sum(1 for k in high_risk_keys if signals.get(k))

    # Base continuous confidence from score (normalized 0..1)
    raw_confidence = score / 3.0
    confidence = float(max(0.0, min(1.0, raw_confidence)))

    # Boost confidence when multiple high-risk signals are present so the
    # result approaches critical, while preserving the final gate below.
    if high_risk_count >= 3:
        confidence = max(confidence, 0.99)
    elif high_risk_count == 2:
        # Two high-risk signals => near-critical confidence
        confidence = max(confidence, 0.96)
    elif has_critical_combo:
        # Known critical combo gives a strong signal
        confidence = max(confidence, 0.98)

    # Enforce policy: confidence > 0.95 (Critical) only when there are
    # at least two high-risk signals or a known critical combo trigger.
    if confidence > 0.95 and not (high_risk_count >= 2 or has_critical_combo):
        confidence = 0.95

    return {
        "scamDetected": bool(scam_detected),
        "score": score,
        "confidenceLevel": confidence,
        "triggers": _dedupe_preserve_order(active_signals + combo_triggers),
    }


def detect_scam(text: str, *, extracted: dict[str, Any] | None = None) -> ScamSignals:
    behavior = detect_behavioral_signals(text, extracted=extracted)
    result = compute_scam_score(behavior)
    return ScamSignals(
        scamDetected=bool(result.get("scamDetected", False)),
        score=float(result.get("score", 0.0)),
        confidenceLevel=float(result.get("confidenceLevel", 0.0)),
        triggers=list(result.get("triggers") or []),
    )


def update_session_state(
    *,
    session_id: str,
    incoming_message: MessageContent,
    conversation_history: Sequence[MessageContent] | None,
    server_history: Sequence[MessageContent] | None,
) -> dict[str, Any]:
    """Merge client-provided conversationHistory with server history and compute per-session metrics."""

    merged: list[MessageContent] = []
    seen: set[tuple[str, str, int]] = set()

    def add(msg: Any):
        if not isinstance(msg, MessageContent):
            msg = _coerce_message_like(msg)
        sender = (msg.sender or "").strip().lower()
        text = (msg.text or "").strip()
        ts = _safe_int(getattr(msg, "timestamp", 0), 0)
        key = (sender, text, ts)
        if key in seen:
            return
        seen.add(key)
        merged.append(MessageContent(sender=msg.sender, text=msg.text, timestamp=ts))

    for m in (server_history or []):
        add(m)

    for m in (conversation_history or []):
        add(m)

    add(incoming_message)

    # Compute engagement timestamps from all message timestamps (epoch ms).
    timestamps = [m.timestamp for m in merged if _safe_int(m.timestamp, 0) > 0]
    start_ts = min(timestamps) if timestamps else 0
    last_ts = max(timestamps) if timestamps else 0

    # turnCount = number of honeypot replies so far (completed back-and-forth turns)
    turn_count = sum(1 for m in merged if (m.sender or "").strip().lower() == "honeypot")

    scammer_text = _history_scammer_text(merged)
    intel = extract_intelligence(scammer_text)
    signals = detect_scam(scammer_text, extracted=intel)

    return {
        "sessionId": session_id,
        "history": merged,
        "messageCount": int(len(merged)),
        "turnCount": int(turn_count),
        "startTimestamp": int(start_ts),
        "lastTimestamp": int(last_ts),
        "extractedIntelligence": intel,
        "scamSignals": signals,
    }


_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _shape_reply(text: str, *, fallback: str) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        cleaned = fallback
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(cleaned) if p.strip()]
    if parts:
        cleaned = " ".join(parts[:3]).strip()

    if "?" not in cleaned:
        if not cleaned.endswith((".", "!", "?")):
            cleaned += "."
        cleaned += " Can you share your employee ID and a complaint/reference number so I can verify?"

    return cleaned


def _contains_investigative_question(text: str) -> bool:
    low = (text or "").lower()
    return any(q.lower() in low for q in _INVESTIGATIVE_QUESTIONS)


def _force_investigative_question(reply: str, question: str) -> str:
    """Ensure reply includes a specific investigative question within 1–3 sentences."""

    cleaned = (reply or "").strip()
    if not cleaned:
        cleaned = question

    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(cleaned) if p.strip()]

    # If already contains an investigative question, keep as-is.
    if _contains_investigative_question(cleaned):
        return cleaned

    # Replace last sentence if we already have 3; otherwise append.
    if len(parts) >= 3:
        parts = parts[:2] + [question]
    else:
        if parts and not cleaned.endswith((".", "!", "?")):
            cleaned += "."
        parts = [p.strip() for p in _SENTENCE_SPLIT_RE.split(cleaned) if p.strip()]
        if len(parts) >= 3:
            parts = parts[:2] + [question]
        else:
            parts.append(question)

    return " ".join(parts[:3]).strip()


_SYSTEM_INSTRUCTION = (
    "You are an AI-powered conversational honeypot engaging a suspected scammer. "
    "Your goal is to keep them talking while collecting verifiable identifiers (employee ID, department, case/reference number, "
    "official website, supervisor contact, branch/office address, official email, phone, UPI, bank account, URLs). "
    "Persona: cautious but cooperative; slightly confused; sometimes elderly; asks to repeat slowly. "
    "Safety: never share real personal data; never share OTP/PIN/password; never click links; never accuse directly. "
    "Style: English only; 1-3 short sentences; always include at least one question. "
    "Output: reply text only (no JSON, no analysis, no markdown)."
)

_client: Groq | None = None
_client_init_attempted = False


def _get_client() -> Groq | None:
    global _client, _client_init_attempted
    if _client_init_attempted:
        return _client
    _client_init_attempted = True
    if not GROQ_API_KEY:
        _client = None
        return None
    try:
        _client = Groq(api_key=GROQ_API_KEY)
        return _client
    except Exception:
        logger.exception("Failed to initialize Groq client; using fallback replies.")
        _client = None
        return None


_INVESTIGATIVE_QUESTIONS = [
    "What is your employee ID?",
    "Please share your official website.",
    "What is your branch code?",
    "Can you provide a complaint reference number?",
    "Who is your supervisor?",
    "What is your registered office address?",
    "Can you verify via official email?",
    "What is the official helpline number?",
]

_DELAY_TACTICS = [
    "I didn't receive the OTP, can you resend?",
    "The link is not opening, can you share again?",
    "Please explain slowly, I'm elderly.",
    "My network is weak, can you repeat?",
    "I am not very technical, can you guide me step by step?",
]


def _extract_used_investigative_questions(history_items: Sequence[MessageContent]) -> set[str]:
    used: set[str] = set()
    for m in history_items:
        if (m.sender or "").strip().lower() != "honeypot":
            continue
        text = (m.text or "")
        low = text.lower()
        for q in _INVESTIGATIVE_QUESTIONS:
            if q.lower() in low:
                used.add(q)
    return used


def _extract_used_delay_tactics(history_items: Sequence[MessageContent]) -> set[str]:
    """Return which delay tactic strings have already been used by the honeypot in this session."""
    used: set[str] = set()
    for m in history_items:
        if (m.sender or "").strip().lower() != "honeypot":
            continue
        text = (m.text or "").lower()
        for d in _DELAY_TACTICS:
            # Match by substring to tolerate slight phrasing differences
            if d.lower() in text:
                used.add(d)
    return used


def generate_reply(*, session_state: dict[str, Any], persona_facts: Sequence[str] | None = None, channel: str | None = None) -> tuple[str, str]:
    """Generate a 1–3 sentence conversational reply plus internal agentNotes."""

    history_items: list[MessageContent] = list(session_state.get("history") or [])
    scam_signals: ScamSignals = session_state.get("scamSignals")
    extracted = session_state.get("extractedIntelligence") or {
        "phoneNumbers": [],
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "emailAddresses": [],
    }

    # Determine missing intel to ask for.
    missing: list[str] = []
    if not extracted.get("phoneNumbers"):
        missing.append("phone number")
    if not extracted.get("upiIds"):
        missing.append("UPI ID")
    if not extracted.get("bankAccounts"):
        missing.append("bank account number")
    if not extracted.get("phishingLinks"):
        missing.append("official website URL")

    # Stable variety per session + turn.
    seed = f"{session_state.get('sessionId')}:{session_state.get('messageCount', 0)}"
    rnd = random.Random(seed)

    used_questions = _extract_used_investigative_questions(history_items)
    available = [q for q in _INVESTIGATIVE_QUESTIONS if q not in used_questions]
    if not available:
        available = list(_INVESTIGATIVE_QUESTIONS)

    question_1 = rnd.choice(available)
    question_2_pool = [q for q in available if q != question_1] or [q for q in _INVESTIGATIVE_QUESTIONS if q != question_1]
    question_2 = rnd.choice(question_2_pool)

    # Rotate delay tactics: avoid repeating the same excuse until all have been used.
    used_delays = _extract_used_delay_tactics(history_items)
    available_delays = [d for d in _DELAY_TACTICS if d not in used_delays]
    if not available_delays:
        # All used; allow reuse but keep deterministic choice.
        available_delays = list(_DELAY_TACTICS)
    delay = rnd.choice(available_delays)

    # Ensure at least ~50% investigative questions.
    # Use turn parity for determinism (avoids long streaks of non-investigative prompts).
    turn_count = int(session_state.get("turnCount") or 0)
    include_investigative = (turn_count % 2 == 0)

    # Push engagement early: keep investigative questions more frequent before ~8 turns.
    if turn_count < 8:
        include_investigative = True

    # Keep agentNotes subtle but useful.
    triggers = getattr(scam_signals, "triggers", []) if scam_signals else []
    notes_parts: list[str] = []
    if triggers:
        notes_parts.append("Behavioral red flags: " + ", ".join(triggers) + ".")
    if missing:
        notes_parts.append("Still missing: " + ", ".join(missing) + ".")
    agent_notes = " ".join(notes_parts) or "Continue verification-style questioning to elicit identifiers."

    # Build LLM prompt.
    lines = _history_lines(history_items)
    context = "\n".join(lines)
    if MAX_CONTEXT_CHARS and len(context) > MAX_CONTEXT_CHARS:
        context = context[-MAX_CONTEXT_CHARS:]

    persona = ", ".join([str(f) for f in (persona_facts or []) if str(f).strip()])
    missing_hint = ", ".join(missing) if missing else "none"

    # Encourage 10+ messages: ask 2 questions early when possible.
    message_count = int(session_state.get("messageCount") or 0)
    want_two_questions = (message_count < 10) and include_investigative

    prompt_questions = ""
    if include_investigative:
        if want_two_questions:
            prompt_questions = (
                "Ask 2 short investigative questions (choose naturally):\n"
                f"- {question_1}\n- {question_2}\n\n"
            )
        else:
            prompt_questions = (
                "Ask 1 short investigative question (choose naturally):\n"
                f"- {question_1}\n\n"
            )
    else:
        prompt_questions = "Ask one simple clarification question to keep them talking.\n\n"

    user_prompt = (
        "Conversation so far:\n" + context + "\n\n"
        f"Channel: {channel or 'unknown'}\n"
        f"Keep persona consistent with these facts (if any): {persona or 'none'}\n"
        f"Scammer pressure level: {'high' if (scam_signals and scam_signals.score >= 0.6) else 'medium'}\n"
        f"Missing intel to ask for: {missing_hint}\n\n"
        f"Include one gentle delay tactic like: {delay}\n"
        + prompt_questions
        + "Write ONLY your next reply in English (1–3 short sentences), cautious but cooperative, slightly confused, and include at least one question."
    )

    client = _get_client()
    if client is None:
        if include_investigative and want_two_questions:
            fallback = f"{delay} {question_1} Also, {question_2}"
        elif include_investigative:
            fallback = f"{delay} {question_1}"
        else:
            fallback = f"{delay} Can you repeat the steps again?"
        shaped = _shape_reply(fallback, fallback=fallback)
        if include_investigative:
            shaped = _force_investigative_question(shaped, question_1)
        return shaped, agent_notes

    try:
        # Groq SDK doesn’t expose a universal timeout arg across versions; rely on outer fail_after.
        system_content = _SYSTEM_INSTRUCTION + (f" Channel: {channel}." if channel else "")
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.6,
            max_tokens=120,
        )
        raw = (response.choices[0].message.content or "").strip()
        if include_investigative and want_two_questions:
            fallback = f"{delay} {question_1} Also, {question_2}"
        elif include_investigative:
            fallback = f"{delay} {question_1}"
        else:
            fallback = f"{delay} Can you repeat the steps again?"
        shaped = _shape_reply(raw, fallback=fallback)
        if include_investigative:
            shaped = _force_investigative_question(shaped, question_1)
        return shaped, agent_notes
    except Exception:
        logger.exception("LLM reply generation failed; using fallback.")
        if include_investigative and want_two_questions:
            fallback = f"{delay} {question_1} Also, {question_2}"
        elif include_investigative:
            fallback = f"{delay} {question_1}"
        else:
            fallback = f"{delay} Can you repeat the steps again?"
        shaped = _shape_reply(fallback, fallback=fallback)
        if include_investigative:
            shaped = _force_investigative_question(shaped, question_1)
        return shaped, agent_notes


def generate_final_output(*, session_id: str, history_items: Sequence[MessageContent]) -> dict[str, Any]:
    normalized_history = [_coerce_message_like(m) if not isinstance(m, MessageContent) else m for m in (history_items or [])]
    scammer_text = _history_scammer_text(normalized_history)
    extracted = extract_intelligence(scammer_text)
    signals = detect_scam(scammer_text, extracted=extracted)

    agent_notes_parts: list[str] = []
    if signals.triggers:
        agent_notes_parts.append("Behavioral red flags: " + ", ".join(signals.triggers) + ".")
    if extracted.get("phishingLinks"):
        agent_notes_parts.append("Links were shared; request an official domain and reference number.")
    if extracted.get("upiIds") or extracted.get("bankAccounts"):
        agent_notes_parts.append("Payment identifiers appeared; ask for beneficiary name and bank details for verification.")
    if extracted.get("emailAddresses"):
        agent_notes_parts.append("Ask to verify via official email channel.")
    agent_notes = " ".join(agent_notes_parts) or "Continue cautious verification questioning to elicit identifiers."

    return {
        "sessionId": session_id,
        "scamDetected": bool(signals.scamDetected),
        "totalMessagesExchanged": int(len(list(normalized_history))),
        "engagementDurationSeconds": int(_engagement_duration_seconds(normalized_history)),
        "extractedIntelligence": {
            "phoneNumbers": list(extracted.get("phoneNumbers") or []),
            "bankAccounts": list(extracted.get("bankAccounts") or []),
            "upiIds": list(extracted.get("upiIds") or []),
            "phishingLinks": list(extracted.get("phishingLinks") or []),
            "emailAddresses": list(extracted.get("emailAddresses") or []),
        },
        "agentNotes": str(agent_notes),
        "confidenceLevel": float(max(0.0, min(1.0, signals.confidenceLevel))),
    }
