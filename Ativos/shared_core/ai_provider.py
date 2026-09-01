"""Seleção compartilhada de provedor de IA com fallback."""

from __future__ import annotations


def provider_order(preferred: str, availability: dict[str, bool], defaults: tuple[str, ...]) -> list[str]:
    normalized = (preferred or "auto").strip().lower()
    if normalized in availability:
        requested = (normalized, *(name for name in defaults if name != normalized))
    else:
        requested = defaults
    return [name for name in requested if availability.get(name, False)]
