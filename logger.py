import csv
import os
from datetime import datetime

FILE_PATH = "data/scam_logs.csv"

_HEADER = [
    "timestamp",
    "session_id",
    "event_type",
    "sender",
    "message",
    "scam_detected",
    "confidence_score",
    "upi_ids",
    "bank_accounts",
    "ifsc_codes",
    "phishing_urls",
    "phone_numbers",
    "suspicious_phrases",
    "sophistication",
]

def _ensure_header_up_to_date():
    if not os.path.isfile(FILE_PATH):
        return
    try:
        with open(FILE_PATH, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        if not rows:
            return
        if rows[0] != _HEADER:
            rows[0] = _HEADER
            with open(FILE_PATH, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
    except Exception:
        # If header repair fails, leave file as-is to avoid data loss
        pass

def _ensure_writer(writer):
    if not os.path.isfile(FILE_PATH):
        writer.writerow(_HEADER)

def _join_list(values):
    return ",".join([str(v) for v in values if v])

def log_message_event(
    session_id: str,
    sender: str,
    message: str,
    intel: dict | None = None,
    confidence: float | None = None,
    scam_detected: bool | None = None,
    suspicious_phrases: list | None = None,
):
    intel = intel or {}
    _ensure_header_up_to_date()
    with open(FILE_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        _ensure_writer(writer)
        writer.writerow([
            datetime.utcnow().isoformat(),
            session_id,
            "message",
            sender,
            message,
            bool(scam_detected) if scam_detected is not None else "",
            float(confidence) if confidence is not None else "",
            _join_list(intel.get("upi_ids", [])),
            _join_list(intel.get("bank_accounts", [])),
            _join_list(intel.get("ifsc_codes", [])),
            _join_list(intel.get("phishing_urls", [])),
            _join_list(intel.get("phone_numbers", [])),
            _join_list(suspicious_phrases or []),
            "",
        ])

def log_summary_event(
    session_id: str,
    intel: dict,
    suspicious_phrases: list | None = None,
    sophistication: str | None = None,
):
    _ensure_header_up_to_date()
    with open(FILE_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        _ensure_writer(writer)
        writer.writerow([
            datetime.utcnow().isoformat(),
            session_id,
            "summary",
            "",
            "",
            True,
            "",
            _join_list(intel.get("upi_ids", [])),
            _join_list(intel.get("bank_accounts", [])),
            _join_list(intel.get("ifsc_codes", [])),
            _join_list(intel.get("phishing_urls", [])),
            _join_list(intel.get("phone_numbers", [])),
            _join_list(suspicious_phrases or []),
            sophistication or "",
        ])

# Backwards-compatible wrapper
def log_scam(session_id, intel, confidence):
    log_message_event(
        session_id=session_id,
        sender="system",
        message="legacy_log_scam",
        intel=intel,
        confidence=confidence,
        scam_detected=True,
    )
