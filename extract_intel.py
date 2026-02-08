import re

_NON_DIGIT = re.compile(r"\D+")
_NON_ALNUM = re.compile(r"[^A-Z0-9]+")

def _normalize_bank_account(raw: str) -> str | None:
    digits = _NON_DIGIT.sub("", raw)
    # Avoid misclassifying phone numbers as bank accounts
    if len(digits) == 10 and digits[0] in {"6", "7", "8", "9"}:
        return None
    if len(digits) == 12 and digits.startswith("91") and digits[2] in {"6", "7", "8", "9"}:
        return None
    if 9 <= len(digits) <= 18:
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
    # Accept 10-digit local or 12-digit with country code 91
    if len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    if len(digits) == 10:
        return f"+91{digits}"
    return None


def extract_intel(text: str):
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    bank_pattern = r"\b(?:\d[ -]?){9,20}\b"
    # Strict IFSC pattern: 4 letters + 0 + 6 digits
    ifsc_pattern = r"\b[A-Z]{4}0\d{6}\b"
    url_pattern = r"https?://[^\s]+"
    phone_pattern = r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b"

    upis_raw = [u for u in re.findall(upi_pattern, text) if "http" not in u.lower()]
    upis = {_normalize_upi(u) for u in upis_raw}

    bank_candidates = re.findall(bank_pattern, text)
    bank_accounts = set()
    for candidate in bank_candidates:
        normalized = _normalize_bank_account(candidate)
        if normalized:
            bank_accounts.add(normalized)

    ifsc_candidates = re.findall(ifsc_pattern, text.upper())
    ifsc_codes = set()
    for candidate in ifsc_candidates:
        normalized = _normalize_ifsc(candidate)
        if normalized:
            ifsc_codes.add(normalized)

    phones_raw = re.findall(phone_pattern, text)
    phone_numbers = set()
    for raw in phones_raw:
        normalized = _normalize_phone(raw)
        if normalized:
            phone_numbers.add(normalized)

    return {
        "upi_ids": sorted(upis),
        "bank_accounts": sorted(bank_accounts),
        "ifsc_codes": sorted(ifsc_codes),
        "phone_numbers": sorted(phone_numbers),
        "phishing_urls": sorted(set(re.findall(url_pattern, text))),
    }
