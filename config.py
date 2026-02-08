import os
import logging
from dotenv import load_dotenv

# Force load the .env file from the current directory
load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

if not API_KEY:
    raise ValueError("HONEYPOT_API_KEY missing. Set it in .env or environment.")
if not GROQ_API_KEY:
    logging.getLogger(__name__).warning(
        "GROQ_API_KEY missing; LLM features will be disabled and a safe fallback reply will be used."
    )

MAX_HISTORY = int(os.getenv("MAX_HISTORY", "50"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "8000"))
