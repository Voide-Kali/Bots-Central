"""Exemplo de configuração; copie para config.py ou use um arquivo .env."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ATIVOS_DIR = Path(__file__).resolve().parents[1]
if str(ATIVOS_DIR) not in sys.path:
    sys.path.insert(0, str(ATIVOS_DIR))

from shared_core.ai_provider import provider_order
from shared_core.telegram_auth import parse_allowed_chat_ids


def env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, value)

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_FALLBACK_MODEL = os.environ.get("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")
AI_PROVIDER = os.environ.get("AI_PROVIDER", "auto").lower()
ALLOWED_CHAT_IDS_RAW = os.environ.get("ALLOWED_CHAT_IDS", "")
MAX_PDF_MB = env_int("MAX_PDF_MB", 20)
MAX_DOCUMENT_CHARS = env_int("MAX_DOCUMENT_CHARS", 60000, minimum=12000)
MAX_HISTORY_MESSAGES = env_int("MAX_HISTORY_MESSAGES", 20, minimum=2)


def active_ai_provider() -> str:
    providers = provider_order(
        AI_PROVIDER,
        {"gemini": bool(GEMINI_API_KEY), "groq": bool(GROQ_API_KEY)},
        ("gemini", "groq"),
    )
    return providers[0] if providers else "indisponivel"


def fallback_ai_provider(primary: str) -> str | None:
    providers = provider_order(
        primary,
        {"gemini": bool(GEMINI_API_KEY), "groq": bool(GROQ_API_KEY)},
        ("gemini", "groq"),
    )
    return providers[1] if len(providers) > 1 else None


def allowed_chat_ids() -> set[int] | None:
    return parse_allowed_chat_ids(ALLOWED_CHAT_IDS_RAW)
