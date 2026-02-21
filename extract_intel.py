import re
import html
import urllib.parse
from typing import Iterable, Sequence

_NON_DIGIT = re.compile(r"\D+")
_NON_ALNUM = re.compile(r"[^A-Z0-9]+")

# Spec: Emails
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Spec: URLs
_URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:/[^\s]*)?", re.IGNORECASE)

# Spec: Phone numbers
_PHONE_RE = re.compile(r"\+?\d[\d\s\-]{8,15}")

# Spec: Bank accounts (digits only). Allow a wide range of lengths and
# loose formatting (spaces, dashes, brackets, dots). We'll still prefer
# phone normalization for obvious phone-like patterns.
_BANK_DIGITS_RE = re.compile(r"\b\d{6,30}\b")
_BANK_LOOSE_RE = re.compile(r"\b(?:\d[\s\-\.\(\)\[\]]?){6,40}\b")

# Spec: UPI IDs (name@bank) – email addresses excluded separately.
_UPI_RE = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9._-]{1,64}@[a-zA-Z0-9_-]{2,64}\b")


def _normalize_obfuscation(text: str) -> str:
    t = (text or "")
    t = t.lower()

    # Common scam obfuscations for URLs and handles.
    t = re.sub(r"\[\s*\.\s*\]", ".", t)
    t = re.sub(r"\(\s*\.\s*\)", ".", t)
    t = re.sub(r"(?<=\w)\s+dot\s+(?=\w)", ".", t)
    # handle d-o-t, d.o.t, d o t, and bracketed dot-like variations (with optional surrounding dashes)
    t = re.sub(r"-?[dD][\s.\-_]*[oO0][\s.\-_]*[tT]-?", ".", t)
    t = re.sub(r"\b(at)\b", "@", t)
    t = re.sub(r"\[\s*at\s*\]|\(\s*at\s*\)", "@", t)

    # Handle "colon" and "slash" words with optional surrounding dashes
    # Match "colon" with internal and external dashes
    t = re.sub(r"-?c[\s.\-_]*o[\s.\-_]*l[\s.\-_]*o[\s.\-_]*n-?", ":", t)
    # Match "slash" with internal and external dashes
    t = re.sub(r"-?s[\s.\-_]*l[\s.\-_]*a[\s.\-_]*s[\s.\-_]*h-?", "/", t)

    # Normalize hxxp / hxxps and split-letter http variants.
    t = re.sub(r"\bhxxps\b", "https", t)
    t = re.sub(r"\bhxxp\b", "http", t)
    t = re.sub(r"h\s*[-._]*t\s*[-._]*t\s*[-._]*p\s*[-._]*s", "https", t)
    t = re.sub(r"h\s*[-._]*t\s*[-._]*t\s*[-._]*p", "http", t)

    # Handle spaced letters like "h t t p s" more generally
    t = re.sub(r"h(\s|[-._])*t(\s|[-._])*t(\s|[-._])*p(\s|[-._])*s?", lambda m: "https" if "s" in m.group(0) else "http", t)

    # Normalize "http colon slash slash" and bracketed separators.
    t = re.sub(r"https?\s*(\[\s*:\s*\]|:)\s*(slash\s*slash|/\s*/)", "https://", t)
    t = re.sub(r"https?\s+colon\s+slash\s+slash", "https://", t)
    t = re.sub(r"https?\s*colon\s*//", "https://", t)
    t = re.sub(r"\bslash\b", "/", t)

    # Clean spacing artifacts around separators.
    t = re.sub(r"\s*@\s*", "@", t)
    t = re.sub(r"\s*/\s*", "/", t)
    t = re.sub(r"https://\s+", "https://", t)
    t = re.sub(r"http://\s+", "http://", t)
    t = re.sub(r"\s+", " ", t).strip()
    # Unescape HTML entities (e.g. &#46; -> .) and percent-encoded sequences
    try:
        t = html.unescape(t)
    except Exception:
        pass
    try:
        # unquote will convert %3A%2F%2F -> :// so subsequent regexes can normalize
        t = urllib.parse.unquote(t)
    except Exception:
        pass

    # Final clean pass: collapse repeated separators and stray spaces
    t = re.sub(r"\s+", " ", t).strip()

    # Collapse spaced single-letter obfuscations like "e x a m p l e . c o m"
    def _collapse_spaced_letters(m: re.Match) -> str:
        return re.sub(r"\s+", "", m.group(0))

    try:
        t = re.sub(r"\b(?:[a-zA-Z]\s+){2,}[a-zA-Z]\b", _collapse_spaced_letters, t)
    except Exception:
        pass

    # Collapse spaced/dashed digit sequences that represent phone numbers or
    # bank account numbers (e.g., "8 8 0 0 1 2 3 4 5 6" -> "8800123456").
    def _collapse_spaced_digits(m: re.Match) -> str:
        s = re.sub(r"[^0-9]", "", m.group(0))
        return s

    try:
        # Match sequences of digits separated by spaces, dots or dashes, with
        # at least 9 digits total (covers phones and many bank accounts).
        t = re.sub(r"(?:\d[\s\-\.\[\]\(\)]?){9,}", _collapse_spaced_digits, t)
    except Exception:
        pass

    return t

def _normalize_bank_account(raw: str) -> str | None:
    digits = _NON_DIGIT.sub("", raw)
    if not digits:
        return None

    # Keep phone-safety heuristics to avoid misclassifying common mobile numbers
    # India 10-digit mobiles starting 6/7/8/9 -> likely phone
    if len(digits) == 10 and digits[0] in {"6", "7", "8", "9"}:
        return None
    # International pattern: 12-digit starting with country code 91 + 10-digit mobile
    if len(digits) == 12 and digits.startswith("91") and digits[2] in {"6", "7", "8", "9"}:
        return None

    # Accept a broad range of lengths as potential bank accounts (6..24 digits)
    if 6 <= len(digits) <= 30:
        return digits
    return None

def _normalize_ifsc(raw: str) -> str | None:
    cleaned = _NON_ALNUM.sub("", raw.upper())
    # Strict IFSC format: 4 letters + 0 + 6 digits
    if re.fullmatch(r"[A-Z]{4}0\d{6}", cleaned):
        return cleaned
    return None

def _normalize_upi(raw: str) -> str:
    # Strip common trailing punctuation and whitespace
    return raw.strip().strip(".,;:()[]{}<>").lower()

def _normalize_phone(raw: str) -> str | None:
    digits = _NON_DIGIT.sub("", raw)
    if not digits:
        return None
    # Normalize common India patterns; otherwise fall back to E.164-like +digits.
    if len(digits) == 10 and digits[0] in {"6", "7", "8", "9"}:
        return "+91" + digits
    if len(digits) == 12 and digits.startswith("91"):
        return "+" + digits
    # Accept 9–15 digit phones (covers most international formats).
    if 9 <= len(digits) <= 15:
        return "+" + digits
    return None


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _extract_emails(text: str) -> list[str]:
    emails = [e.strip().lower() for e in _EMAIL_RE.findall(text or "")]
    return _dedupe_preserve_order([e for e in emails if e])


def _looks_like_upi(value: str) -> bool:
    """Return True if value resembles a UPI ID (generic heuristic).

    Rule: must contain exactly one '@' and the domain part must NOT contain a dot.
    This avoids classifying standard emails (which typically have a dotted domain).
    """

    if not value or value.count("@") != 1:
        return False
    handle, domain = value.split("@", 1)
    if not handle or not domain:
        return False
    if "." in domain:
        return False
    return True


def _coerce_text(text_or_texts: str | Sequence[str]) -> str:
    if isinstance(text_or_texts, str):
        return text_or_texts
    parts: list[str] = []
    for t in text_or_texts:
        if t is None:
            continue
        s = str(t)
        if s.strip():
            parts.append(s)
    return "\n".join(parts)


def extract_intel(text_or_texts: str | Sequence[str]):
    text = _coerce_text(text_or_texts)
    normalized_text = _normalize_obfuscation(text)

    # Extract emails first so they don't get misclassified as UPI IDs.
    emails = _extract_emails(normalized_text)
    email_addresses = set(emails)

    # IMPORTANT: remove emails from the text before running UPI extraction.
    # Otherwise a UPI regex can incorrectly match the prefix of an email
    # (e.g., support@fakebank-secure in support@fakebank-secure.com).
    cleaned_text = _EMAIL_RE.sub(" ", normalized_text or "")

    # UPI IDs
    upis_raw = [u for u in _UPI_RE.findall(cleaned_text) if "http" not in u.lower()]
    upis: set[str] = set()
    for raw in upis_raw:
        normalized = _normalize_upi(raw)
        if not normalized:
            continue
        if normalized in email_addresses:
            continue
        # Extra safeguard: if an email starts with this UPI + '.', it's a truncated email match.
        if any(email.startswith(normalized + ".") for email in email_addresses):
            continue
        if not _looks_like_upi(normalized):
            continue
        upis.add(normalized)

    # Bank accounts (handle both contiguous and spaced/dashed forms)
    bank_candidates: list[str] = []
    bank_candidates.extend(_BANK_DIGITS_RE.findall(normalized_text))
    bank_candidates.extend(_BANK_LOOSE_RE.findall(normalized_text))
    bank_accounts = set()
    for candidate in bank_candidates:
        # Determine if surrounding context suggests this is a phone number
        phone_context_terms = ("phone", "call", "mobile", "whatsapp", "contact")
        phone_like = _normalize_phone(candidate)
        is_phone_context = False
        try:
            idx = normalized_text.find(candidate)
            if idx != -1:
                window = normalized_text[max(0, idx - 30): idx + len(candidate) + 30].lower()
                if any(term in window for term in phone_context_terms):
                    is_phone_context = True
        except Exception:
            is_phone_context = False

        # If candidate explicitly includes a plus sign or context implies a phone,
        # prefer phone normalization and skip bank classification.
        if ("+" in candidate or phone_like) and ("+" in candidate or phone_like and is_phone_context):
            continue
        normalized = _normalize_bank_account(candidate)
        if normalized:
            bank_accounts.add(normalized)

    # Keep IFSC extraction (internal) if present; it can help downstream scoring.
    ifsc_candidates = re.findall(r"\b[A-Z]{4}0\d{6}\b", normalized_text.upper())
    ifsc_codes = set()
    for candidate in ifsc_candidates:
        normalized = _normalize_ifsc(candidate)
        if normalized:
            ifsc_codes.add(normalized)

    phones_raw = _PHONE_RE.findall(normalized_text)
    phone_numbers = set()
    # Build a set of bank digit strings to avoid double-classifying the same
    # digit sequence as both a bank account and a phone number.
    bank_digits_set = set(bank_accounts)
    for raw in phones_raw:
        # Extract raw digits for overlap checks
        raw_digits = _NON_DIGIT.sub("", raw)
        # If raw digits overlap with any detected bank account digits, prefer bank
        overlap = False
        for b in bank_digits_set:
            if not b:
                continue
            if b in raw_digits or raw_digits in b:
                overlap = True
                break
        if overlap:
            continue

        normalized = _normalize_phone(raw)
        if normalized:
            phone_numbers.add(normalized)

    # Build phishing URL set: include explicit http(s) URLs and domain-only links
    urls_set: set[str] = set()
    for u in _URL_RE.findall(normalized_text):
        urls_set.add(u)
    for d in _DOMAIN_RE.findall(normalized_text):
        if "@" in d:
            # likely part of an email, skip
            continue
        # skip if already present (substring match)
        if any(d in u for u in urls_set):
            continue
        if not re.match(r"https?://", d, re.IGNORECASE):
            urls_set.add("http://" + d)
        else:
            urls_set.add(d)

    return {
        "upi_ids": sorted(upis),
        "bank_accounts": sorted(bank_accounts),
        "ifsc_codes": sorted(ifsc_codes),
        "phone_numbers": sorted(phone_numbers),
        "phishing_urls": sorted(urls_set),
    }


def extract_intelligence(text_or_texts: str | Sequence[str]) -> dict:
    """Extract actionable intelligence with clean separation of UPI IDs vs emails.

    Returns camelCase keys and always-present arrays:
    {
      "phoneNumbers": [],
      "bankAccounts": [],
      "upiIds": [],
      "phishingLinks": [],
      "emailAddresses": []
    }
    """

    text = _coerce_text(text_or_texts)
    normalized_text = _normalize_obfuscation(text)
    emails = _extract_emails(normalized_text)
    snake = extract_intel(normalized_text)
    email_set = set(emails)
    upis = []
    for u in (snake.get("upi_ids") or []):
        candidate = str(u).lower().strip()
        if not candidate:
            continue
        if candidate in email_set:
            continue
        if any(email.startswith(candidate + ".") for email in email_set):
            continue
        upis.append(candidate)

    return {
        "phoneNumbers": list(snake.get("phone_numbers") or []),
        "bankAccounts": list(snake.get("bank_accounts") or []),
        "upiIds": _dedupe_preserve_order(upis),
        "phishingLinks": list(snake.get("phishing_urls") or []),
        "emailAddresses": emails,
    }
