#!/usr/bin/env python3
from __future__ import annotations

import socket
import subprocess
from datetime import datetime

from notifier import alert_configured, alert_config_error, send_alert


def _cmd_out(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        return (r.stdout or "").strip()
    except Exception:
        return ""


def get_local_ip() -> str:
    ip = _cmd_out(["hostname", "-I"]).split()
    return ip[0] if ip else "desconhecido"


def main() -> int:
    if not alert_configured():
        print(alert_config_error())
        return 0

    host = socket.gethostname()
    ip_local = get_local_ip()
    horario = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    send_alert(
        "BOOT",
        f"PC ligado\nHost: {host}\nIP: {ip_local}\nHorario: {horario}",
        priority=0,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
