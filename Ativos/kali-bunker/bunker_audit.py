#!/usr/bin/env python3
"""Registro local estruturado de eventos operacionais."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


STATE_DIR = Path.home() / ".local" / "state" / "kali-bunker"
AUDIT_LOG = STATE_DIR / "audit.jsonl"


def record_event(event: str, **details: object) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "event": event,
            **details,
        }
        with AUDIT_LOG.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    except OSError:
        # Auditoria é complementar e nunca deve interromper um alerta crítico.
        return
