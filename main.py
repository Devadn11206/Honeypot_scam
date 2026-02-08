from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import asyncio
import logging
import re
import time
import functools
from typing import Any

import anyio

from schemas import MessageContent, HoneypotResponse
from config import API_KEY
from redis_store import append_message, get_history, set_history, mark_callback_sent, redis_available
from agent import generate_agent_response, extract_intelligence_from_history, extract_persona_facts_from_history
from memory import update_persona_facts, get_persona_facts
from callback import send_final_callback
from logger import log_message_event
from hybrid_decision import compute_final_risk
from sophistication import compute_sophistication

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)

app = FastAPI(title="Agentic Honeypot API")
SAFE_FALLBACK_REPLY = "I'm not sure about this. Could you please share the official helpline or website so I can verify?"
LATENCY_SAFE_FALLBACK_REPLY = "I’m not sure I understand. Could you share more details?"


def _empty_intel() -> dict:
    return {
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "phone_numbers": [],
        "phishing_urls": [],
    }


def _normalize_intel(intel: dict | None) -> dict:
    intel = intel or {}
    base = _empty_intel()

    def as_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            items = value
        else:
            items = [value]
        return [str(v) for v in items if v is not None and str(v).strip()]

    non_digit = re.compile(r"\D+")
    non_alnum = re.compile(r"[^A-Z0-9]+")

    def normalize_upi(raw: str) -> str | None:
        cleaned = raw.strip().strip(".,;:()[]{}<>").lower()
        if "@" in cleaned and "http" not in cleaned:
            return cleaned
        return None

    def normalize_phone(raw: str) -> str | None:
        digits = non_digit.sub("", raw)
        if len(digits) == 12 and digits.startswith("91"):
            return f"+{digits}"
        if len(digits) == 10:
            return f"+91{digits}"
        return None

    def normalize_bank_account(raw: str) -> str | None:
        digits = non_digit.sub("", raw)
        # Exclude likely phone numbers
        if len(digits) == 10 and digits[:1] in {"6", "7", "8", "9"}:
            return None
        if len(digits) == 12 and digits.startswith("91") and digits[2:3] in {"6", "7", "8", "9"}:
            return None
        if 9 <= len(digits) <= 18:
            return digits
        return None

    def normalize_ifsc(raw: str) -> str | None:
        cleaned = non_alnum.sub("", raw.upper())
        if len(cleaned) != 11:
            return None
        if cleaned[4] == "O":
            cleaned = cleaned[:4] + "0" + cleaned[5:]
        if re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned):
            return cleaned
        return None

    def normalize_url(raw: str) -> str | None:
        cleaned = raw.strip()
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            return cleaned
        return None

    upis = []
    for item in as_list(intel.get("upi_ids")):
        norm = normalize_upi(item)
        if norm:
            upis.append(norm)

    phones = []
    for item in as_list(intel.get("phone_numbers")):
        norm = normalize_phone(item)
        if norm:
            phones.append(norm)

    banks = []
    for item in as_list(intel.get("bank_accounts")):
        norm = normalize_bank_account(item)
        if norm:
            banks.append(norm)

    ifscs = []
    for item in as_list(intel.get("ifsc_codes")):
        norm = normalize_ifsc(item)
        if norm:
            ifscs.append(norm)

    urls = []
    for item in as_list(intel.get("phishing_urls")):
        norm = normalize_url(item)
        if norm:
            urls.append(norm)

    # Dedupe while preserving order
    def dedupe(seq: list[str]) -> list[str]:
        seen = set()
        out = []
        for s in seq:
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    base["upi_ids"] = dedupe(upis)
    base["bank_accounts"] = dedupe(banks)
    base["ifsc_codes"] = dedupe(ifscs)
    base["phone_numbers"] = dedupe(phones)
    base["phishing_urls"] = dedupe(urls)
    return base

@app.on_event("startup")
def warn_if_redis_unavailable():
    if not redis_available():
        logging.warning("Redis unavailable at startup; falling back to in-memory store.")

@app.get("/")
@app.head("/")
def health_check():
    return {"status": "Agent is awake!", "endpoint": "/honeypot/message"}

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logging.error("VAL_ERROR: %s", exc.errors())
    body = await request.body()
    logging.error("RECEIVED_BODY: %s", body.decode(errors="replace"))
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "message": "Invalid Request Body",
            "details": exc.errors(),
        },
    )

def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default

def _coerce_message(raw: Any, fallback_text: str) -> MessageContent:
    now_ms = int(time.time() * 1000)
    if isinstance(raw, dict):
        sender = raw.get("sender") or "user"
        text = raw.get("text") or raw.get("message") or fallback_text or ""
        timestamp = _safe_int(raw.get("timestamp"), now_ms)
    elif isinstance(raw, str):
        sender = "user"
        text = raw
        timestamp = now_ms
    else:
        sender = "user"
        text = fallback_text or ""
        timestamp = now_ms

    return MessageContent(sender=sender, text=text, timestamp=timestamp)

async def _read_json_or_empty(request: Request) -> dict:
    try:
        payload = await request.json()
        if isinstance(payload, dict):
            return payload
        return {}
    except Exception:
        return {}

async def _handle_message_universal(
    request: Request,
    x_api_key: str | None,
):
    if API_KEY and x_api_key != API_KEY:
        logging.warning("Auth failed for request")
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        payload = await _read_json_or_empty(request)
        session_id = (
            payload.get("sessionId")
            or payload.get("session_id")
            or payload.get("session")
            or f"anonymous-{int(time.time() * 1000)}"
        )

        message_raw = payload.get("message") if isinstance(payload, dict) else None
        message = _coerce_message(message_raw, fallback_text=payload.get("text", ""))

        history_raw = payload.get("conversationHistory") or payload.get("conversation_history")
        history_items = []
        if isinstance(history_raw, list):
            for item in history_raw:
                history_items.append(_coerce_message(item, fallback_text=""))

        # 1. Resolve history (client-provided overrides server state)
        if history_items:
            set_history(session_id, history_items)
        else:
            history_items = get_history(session_id)

        append_message(session_id, message)
        history_items.append(message)
        history = [
            f"{m.sender}: {m.text}" if m.sender else m.text
            for m in history_items
        ]

        # Maintain persona memory across turns
        persona_facts = extract_persona_facts_from_history(history)
        update_persona_facts(session_id, persona_facts)
        persona_facts = get_persona_facts(session_id)
        
        # 2. Get AI analysis (non-blocking)
        logging.info("History passed to LLM: %s", history)
        try:
            agent_data = await anyio.to_thread.run_sync(
                functools.partial(generate_agent_response, history, persona_facts=persona_facts)
            )
        except Exception:
            logging.exception("Agent response failed; using safe fallback reply.")
            agent_data = {
                "agent_reply": SAFE_FALLBACK_REPLY,
                "extracted_intelligence": extract_intelligence_from_history(history),
                "risk_analysis": {"exposure_risk": "low", "reasoning": "Fallback due to agent error"},
            }
    except HTTPException:
        raise
    except Exception:
        logging.exception("Request processing failed; returning latency-safe fallback.")
        return {
            "status": "success",
            "reply": LATENCY_SAFE_FALLBACK_REPLY,
            "scam_detected": False,
            "confidence_score": 0.0,
            "extracted_intelligence": _empty_intel(),
            "sophistication_level": "low",
            "intelligence_value_score": 0,
        }
    
    # 3. Mandatory Callback Trigger
    # Rule: Send if scam is confirmed AND we have at least 5 messages
    extracted = _normalize_intel(agent_data.get("extracted_intelligence"))
    suspicious_phrases = (agent_data.get("risk_analysis") or {}).get("suspicious_phrases") or []
    has_intel = any(extracted.get(key) for key in [
        "bank_accounts",
        "upi_ids",
        "phishing_urls",
        "phone_numbers",
        "ifsc_codes",
    ])

    history_text = "\n".join(history)

    model_detected = bool(agent_data.get("scam_detected"))
    try:
        model_confidence = float(agent_data.get("confidence_score", 0.0))
    except Exception:
        model_confidence = 0.0

    scam_detected, confidence_score = compute_final_risk(
        model_detected=model_detected,
        confidence_score=model_confidence,
        extracted_intelligence=extracted,
    )

    soph = compute_sophistication(history_text, extracted)
    sophistication_level = soph.get("sophistication_level", "low")
    intelligence_value_score = int(soph.get("intelligence_value_score", 0) or 0)

    should_callback = scam_detected and (len(history) >= 5 or has_intel)
    if should_callback and mark_callback_sent(session_id):
        asyncio.create_task(
            anyio.to_thread.run_sync(
                functools.partial(
                    send_final_callback,
                    session_id=session_id,
                    history=history,
                    intelligence=extracted,
                    notes=agent_data.get("reasoning"),
                    risk_analysis=agent_data.get("risk_analysis"),
                )
            )
        )

    # 4. Return the EXACT keys required by Section 8
    reply_text = agent_data.get("agent_reply") or SAFE_FALLBACK_REPLY

    # Hard guard: avoid repeating the exact same honeypot reply
    last_honeypot = ""
    for item in reversed(history_items):
        if getattr(item, "sender", "").lower() == "honeypot":
            last_honeypot = item.text or ""
            break
    if last_honeypot and reply_text.strip().lower() == last_honeypot.strip().lower():
        reply_text = reply_text.rstrip(". ") + ". Also, can you share the official helpline or IFSC code?"
    reply_message = MessageContent(
        sender="honeypot",
        text=reply_text,
        timestamp=int(time.time() * 1000),
    )
    append_message(session_id, reply_message)

    # Log incoming and outgoing messages to CSV
    asyncio.create_task(
        anyio.to_thread.run_sync(
            functools.partial(
                log_message_event,
                session_id=session_id,
                sender=message.sender,
                message=message.text,
                intel=extracted,
                confidence=agent_data.get("confidence_score"),
                scam_detected=agent_data.get("scam_detected"),
                suspicious_phrases=suspicious_phrases,
            )
        )
    )
    asyncio.create_task(
        anyio.to_thread.run_sync(
            functools.partial(
                log_message_event,
                session_id=session_id,
                sender="honeypot",
                message=reply_text,
                intel=extracted,
                confidence=agent_data.get("confidence_score"),
                scam_detected=agent_data.get("scam_detected"),
                suspicious_phrases=suspicious_phrases,
            )
        )
    )

    # Simulated typing delay to reduce bot-like responses and smooth rate limits
    await asyncio.sleep(0.4)

    return {
        "status": "success",
        "reply": reply_text,
        "scam_detected": bool(scam_detected),
        "confidence_score": float(confidence_score),
        "extracted_intelligence": extracted,
        "sophistication_level": sophistication_level,
        "intelligence_value_score": intelligence_value_score,
    }

@app.post("/honeypot/message", response_model=HoneypotResponse)
async def handle_message(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
):
    return await _handle_message_universal(request, x_api_key)

# Robust fallback: accept POSTs to "/" and route to honeypot logic
@app.post("/", response_model=HoneypotResponse)
async def handle_root_post(
    request: Request,
    x_api_key: str | None = Header(None, alias="x-api-key"),
):
    return await _handle_message_universal(request, x_api_key)
