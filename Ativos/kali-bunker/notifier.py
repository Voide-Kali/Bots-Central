#!/usr/bin/env python3
"""Envio centralizado de alertas do Kali Bunker."""

from __future__ import annotations

from pathlib import Path
import time

import requests

from bunker_config import (
    ALERT_PROVIDER,
    PUSHOVER_TOKEN,
    PUSHOVER_USER,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    SUPPORTED_ALERT_PROVIDERS,
)

_SESSION = requests


def _redact_token(text: str) -> str:
    value = str(text)
    if TELEGRAM_BOT_TOKEN:
        value = value.replace(TELEGRAM_BOT_TOKEN, "<telegram-token>")
    return value


def alert_configured() -> bool:
    if ALERT_PROVIDER not in SUPPORTED_ALERT_PROVIDERS:
        return False
    if ALERT_PROVIDER == "pushover":
        return bool(PUSHOVER_TOKEN and PUSHOVER_USER)
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def alert_config_error() -> str:
    if ALERT_PROVIDER not in SUPPORTED_ALERT_PROVIDERS:
        return (
            f"ALERT_PROVIDER invalido: {ALERT_PROVIDER!r}. "
            "Use 'telegram' ou 'pushover'."
        )
    if ALERT_PROVIDER == "pushover":
        return "PUSHOVER_TOKEN/PUSHOVER_USER nao configurados."
    return "TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID nao configurados."


def send_alert(
    title: str,
    message: str,
    *,
    priority: int = 0,
    sound: str | None = None,
    photo_path: str | None = None,
    url: str | None = None,
) -> bool:
    if ALERT_PROVIDER not in SUPPORTED_ALERT_PROVIDERS:
        print(f"[ERRO envio] {alert_config_error()}")
        return False
    if ALERT_PROVIDER == "pushover":
        return _send_pushover(title, message, priority=priority, sound=sound, photo_path=photo_path, url=url)
    return _send_telegram(title, message, photo_path=photo_path, url=url)


def _send_telegram(title: str, message: str, *, photo_path: str | None, url: str | None) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[ERRO envio] {alert_config_error()}")
        return False

    text = f"{title}\n\n{message}"
    if url:
        text = f"{text}\n\n{url}"

    base_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    retries = 3
    delay_seconds = 1
    for attempt in range(retries):
        photo = Path(photo_path) if photo_path else None
        try:
            if photo and photo.exists():
                with photo.open("rb") as image:
                    response = _SESSION.post(
                        f"{base_url}/sendPhoto",
                        data={"chat_id": TELEGRAM_CHAT_ID, "caption": text[:1024]},
                        files={"photo": image},
                        timeout=15,
                    )
            else:
                response = _SESSION.post(
                    f"{base_url}/sendMessage",
                    data={"chat_id": TELEGRAM_CHAT_ID, "text": text},
                    timeout=10,
                )
            response.raise_for_status()
            return True
        except requests.RequestException as exc:
            if attempt == retries - 1:
                print(f"[ERRO envio] {_redact_token(exc)}")
                return False
            time.sleep(delay_seconds)
    return False


def _send_pushover(
    title: str,
    message: str,
    *,
    priority: int,
    sound: str | None,
    photo_path: str | None,
    url: str | None,
) -> bool:
    if not PUSHOVER_TOKEN or not PUSHOVER_USER:
        print(f"[ERRO envio] {alert_config_error()}")
        return False

    data = {
        "token": PUSHOVER_TOKEN,
        "user": PUSHOVER_USER,
        "title": title,
        "message": message,
        "priority": str(priority),
    }
    if sound:
        data["sound"] = sound
    if url:
        data["url"] = url
        data["url_title"] = "Ver no mapa"

    try:
        photo = Path(photo_path) if photo_path else None
        if photo and photo.exists():
            with photo.open("rb") as image:
                response = _SESSION.post(
                    "https://api.pushover.net/1/messages.json",
                    data=data,
                    files={"attachment": ("foto.jpg", image, "image/jpeg")},
                    timeout=15,
                )
        else:
            response = _SESSION.post(
                "https://api.pushover.net/1/messages.json",
                data=data,
                timeout=10,
            )
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        print(f"[ERRO envio] {exc}")
        return False
