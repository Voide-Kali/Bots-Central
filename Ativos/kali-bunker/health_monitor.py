#!/usr/bin/env python3
"""Watchdog que monitora a própria infraestrutura do Kali Bunker."""

from __future__ import annotations

import json
import signal
import time
from pathlib import Path

from bunker_audit import record_event
from bunker_config import get_int
from bunker_health import collect_health
from notifier import send_alert
from state_utils import atomic_write_json


INTERVAL = get_int("HEALTH_CHECK_INTERVAL", 60)
FAILURE_THRESHOLD = get_int("HEALTH_FAILURE_THRESHOLD", 2)
ALERT_COOLDOWN = get_int("HEALTH_ALERT_COOLDOWN", 900)
DISK_CRITICAL = get_int("HEALTH_DISK_CRITICAL", 95)
STATE_FILE = Path.home() / ".local" / "state" / "kali-bunker" / "health-state.json"
REPORT_FILE = Path.home() / ".local" / "state" / "kali-bunker" / "health-latest.json"
running = True


def stop(_signum: int, _frame: object) -> None:
    global running
    running = False


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"failures": {}, "alerted": [], "last_alert": 0}


def save_json(path: Path, payload: dict) -> None:
    atomic_write_json(path, payload)


def main() -> None:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    state = load_state()
    record_event("health_monitor_started")

    while running:
        report = collect_health()
        save_json(REPORT_FILE, report)
        failed_now = set(report["critical_failed"])
        if report["resources"]["disk_percent"] >= DISK_CRITICAL:
            failed_now.add("disk-critical")

        failures = state.setdefault("failures", {})
        for unit in failed_now:
            failures[unit] = int(failures.get(unit, 0)) + 1
        for unit in set(failures) - failed_now:
            failures.pop(unit, None)

        confirmed = {
            unit for unit, count in failures.items() if int(count) >= FAILURE_THRESHOLD
        }
        alerted = set(state.get("alerted", []))
        now = int(time.time())
        new_failures = confirmed - alerted
        cooldown_ok = now - int(state.get("last_alert", 0)) >= ALERT_COOLDOWN

        if new_failures and cooldown_ok:
            units = ", ".join(sorted(new_failures))
            sent = send_alert(
                "🚨 KALI BUNKER DEGRADADO",
                f"Falhas confirmadas: {units}\nHost: {report['host']}",
                priority=1,
                sound="siren",
            )
            record_event("health_failure", units=sorted(new_failures), alert_sent=sent)
            state["last_alert"] = now
            alerted.update(new_failures)

        recovered = alerted - confirmed
        if recovered:
            units = ", ".join(sorted(recovered))
            sent = send_alert(
                "✅ KALI BUNKER RECUPERADO",
                f"Módulos normalizados: {units}\nHost: {report['host']}",
            )
            record_event("health_recovery", units=sorted(recovered), alert_sent=sent)
            alerted.difference_update(recovered)

        state["alerted"] = sorted(alerted)
        save_json(STATE_FILE, state)
        for _ in range(max(1, INTERVAL)):
            if not running:
                break
            time.sleep(1)

    record_event("health_monitor_stopped")


if __name__ == "__main__":
    main()
