"""Helpers compartilhados para autorização Telegram."""

from __future__ import annotations

from typing import Any


def parse_numeric_ids(raw: str, *, allow_negative: bool = True) -> set[int]:
    allowed: set[int] = set()
    for item in str(raw or "").split(","):
        value = item.strip()
        if not value:
            continue
        if not value.lstrip("-").isdigit():
            raise ValueError("lista de IDs deve conter apenas números separados por vírgula")
        parsed = int(value)
        if not allow_negative and parsed < 0:
            raise ValueError("IDs negativos não são permitidos neste contexto")
        allowed.add(parsed)
    return allowed


def parse_allowed_chat_ids(raw: str) -> set[int] | None:
    values = parse_numeric_ids(raw, allow_negative=True)
    return values or None


def is_authorized_update(
    update: Any,
    *,
    expected_chat_id: int,
    allowed_user_ids: set[int],
) -> bool:
    chat = getattr(update, "effective_chat", None)
    user = getattr(update, "effective_user", None)
    return bool(
        chat
        and getattr(chat, "id", None) == expected_chat_id
        and user
        and getattr(user, "id", None) in allowed_user_ids
    )
