#!/usr/bin/env python3
"""Configuracao compartilhada dos scripts do Kali Bunker."""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
SUPPORTED_ALERT_PROVIDERS = ("telegram", "pushover")
ENV_PATHS = (
    PROJECT_DIR / ".env",
    Path.home() / ".config" / "kali-bunker" / ".env",
)


def load_env() -> None:
    for env_path in ENV_PATHS:
        if not env_path.exists():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value


load_env()


def get_config(name: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Variavel {name} nao configurada. Crie um .env baseado em .env.example.")
    return value or ""


def get_int(name: str, default: int) -> int:
    try:
        return int(get_config(name, str(default)))
    except ValueError:
        return default


def get_alert_provider() -> str:
    provider = get_config("ALERT_PROVIDER", "telegram").strip().lower()
    if provider not in SUPPORTED_ALERT_PROVIDERS:
        raise RuntimeError(f"ALERT_PROVIDER invalido: {provider!r}. Use 'telegram' ou 'pushover'.")
    return provider


OPERATIONAL_HOME = Path(get_config("KALI_BUNKER_HOME", str(Path.home()))).expanduser()
ALERT_PROVIDER = get_alert_provider()
PUSHOVER_TOKEN = get_config("PUSHOVER_TOKEN")
PUSHOVER_USER = get_config("PUSHOVER_USER")
TELEGRAM_BOT_TOKEN = get_config("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = get_config("TELEGRAM_CHAT_ID")
TELEGRAM_ALLOWED_CHAT_IDS = get_config("TELEGRAM_ALLOWED_CHAT_IDS", TELEGRAM_CHAT_ID)
TELEGRAM_ALLOWED_USER_IDS = get_config("TELEGRAM_ALLOWED_USER_IDS", TELEGRAM_CHAT_ID)
TELEGRAM_POLL_INTERVAL_SECONDS = get_int("TELEGRAM_POLL_INTERVAL_SECONDS", 2)
IPHONE_MAC = get_config("IPHONE_MAC")
WIFI_INTERFACE = get_config("WIFI_INTERFACE", "wlan0")
KNOWN_MACS_FILE = get_config("KNOWN_MACS_FILE", str(OPERATIONAL_HOME / "macs_conhecidos.txt"))
BANNED_DEVICES_FILE = get_config(
    "BANNED_DEVICES_FILE",
    str(OPERATIONAL_HOME / ".local" / "state" / "kali-bunker" / "banned-devices.json"),
)
PROTECTED_DIR = get_config("PROTECTED_DIR", str(OPERATIONAL_HOME / "Documentos"))
