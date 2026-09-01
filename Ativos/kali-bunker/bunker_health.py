#!/usr/bin/env python3
"""Inventário e diagnóstico compartilhado do Kali Bunker."""

from __future__ import annotations

import os
import pwd
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import psutil

from bunker_config import (
    ALERT_PROVIDER,
    ENV_PATHS,
    IPHONE_MAC,
    KNOWN_MACS_FILE,
    PROTECTED_DIR,
    WIFI_INTERFACE,
)
from notifier import alert_configured
from runtime_integrity import describe_integrity, verify_runtime_integrity


@dataclass(frozen=True)
class ServiceSpec:
    unit: str
    name: str
    short: str
    critical: bool = True
    inactive_ok: bool = False


SERVICES = (
    ServiceSpec("bt-alarm.service", "Bluetooth", "BT", critical=bool(IPHONE_MAC)),
    ServiceSpec("monitor-auth.service", "Autenticação", "AUTH"),
    ServiceSpec("monitor-recursos.service", "Recursos", "CPU"),
    ServiceSpec("monitor-wifi.service", "Rede Wi-Fi", "WIFI"),
    ServiceSpec("network-watch.service", "Mudança de rede", "NET"),
    ServiceSpec(
        "monitor-arquivos.service",
        "Arquivos",
        "FILE",
        critical=Path(PROTECTED_DIR).expanduser().is_dir(),
    ),
    ServiceSpec("kali-bunker-health.service", "Autovigilância", "HEALTH"),
    ServiceSpec("kali-bunker-telegram.service", "Telegram rede", "TG", critical=False),
    ServiceSpec("usbguard.service", "USBGuard", "USB", critical=False),
    ServiceSpec("fail2ban.service", "Fail2Ban", "BAN", critical=False),
    ServiceSpec(
        "notifica-boot.service",
        "Aviso de boot",
        "BOOT",
        critical=False,
        inactive_ok=True,
    ),
    ServiceSpec(
        "notifica-shutdown.service",
        "Aviso de desligamento",
        "OFF",
        critical=False,
        inactive_ok=True,
    ),
    ServiceSpec("limpeza-semanal.timer", "Limpeza semanal", "CLEAN"),
    ServiceSpec("relatorio-semanal.timer", "Relatório semanal", "REPORT"),
)

REQUIRED_COMMANDS = (
    "systemctl",
    "journalctl",
    "ip",
    "hostname",
    "sensors",
    "bluetoothctl",
    "hcitool",
    "inotifywait",
    "arp-scan",
    "nmap",
    "iptables",
)


def run_command(command: list[str], timeout: int = 5) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def systemctl_unavailable(result: subprocess.CompletedProcess[str] | None) -> bool:
    if result is None or result.returncode == 0:
        return False
    message = f"{result.stdout}\n{result.stderr}".lower()
    unavailable_markers = (
        "failed to connect to system scope bus",
        "operation not permitted",
        "system has not been booted with systemd",
        "failed to connect to bus",
    )
    return any(marker in message for marker in unavailable_markers)


def systemd_accessible() -> bool:
    result = run_command(["systemctl", "is-system-running"])
    return result is not None and not systemctl_unavailable(result)


def service_state(unit: str) -> str:
    if unit == "kali-bunker-telegram.service":
        user_result = run_command(["systemctl", "--user", "is-active", unit])
        if user_result is not None and user_result.returncode == 0:
            return user_result.stdout.strip() or "active"
    result = run_command(["systemctl", "is-active", unit])
    if systemctl_unavailable(result):
        return "unavailable"
    if result is None:
        return "unknown"
    state = result.stdout.strip()
    return state or "unknown"


def service_enabled(unit: str) -> str:
    if unit == "kali-bunker-telegram.service":
        user_result = run_command(["systemctl", "--user", "is-enabled", unit])
        if user_result is not None and user_result.returncode == 0:
            return user_result.stdout.strip() or "enabled"
    result = run_command(["systemctl", "is-enabled", unit])
    if systemctl_unavailable(result):
        return "unavailable"
    if result is None:
        return "unknown"
    return result.stdout.strip() or "unknown"


def temperature() -> float | None:
    result = run_command(["sensors"], timeout=4)
    if not result:
        return None
    preferred = ("Package id 0", "Tctl", "Tccd1", "Core 0")
    for sensor_name in preferred:
        for line in result.stdout.splitlines():
            if sensor_name not in line or ":" not in line:
                continue
            raw = line.split(":", 1)[1].strip().split()[0]
            try:
                return float(raw.replace("+", "").replace("°C", ""))
            except ValueError:
                continue
    return None


def local_ips() -> list[str]:
    result = run_command(["hostname", "-I"])
    return result.stdout.split() if result and result.stdout else []


def collect_health() -> dict:
    cpu = psutil.cpu_percent(interval=0.2)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load = os.getloadavg()
    can_query_systemd = systemd_accessible()
    services = []
    for spec in SERVICES:
        services.append(
            {
                **asdict(spec),
                "state": service_state(spec.unit),
                "enabled": service_enabled(spec.unit),
            }
        )
    critical_failed = [
        item["unit"]
        for item in services
        if can_query_systemd and item["critical"] and item["state"] != "active"
    ]
    if not can_query_systemd:
        critical_failed.append("systemd-unavailable")
    integrity = verify_runtime_integrity()
    if not integrity["ok"]:
        critical_failed.append("runtime-integrity")
    return {
        "schema_version": 1,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "ips": local_ips(),
        "systemd_accessible": can_query_systemd,
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "resources": {
            "cpu_percent": cpu,
            "memory_percent": memory.percent,
            "disk_percent": disk.percent,
            "disk_free_gib": round(disk.free / 1024**3, 2),
            "load_1m": round(load[0], 2),
            "load_5m": round(load[1], 2),
            "load_15m": round(load[2], 2),
            "temperature_c": temperature(),
        },
        "services": services,
        "runtime_integrity": integrity,
        "critical_failed": critical_failed,
        "healthy": not critical_failed and disk.percent < 95,
    }


def doctor_checks() -> list[dict[str, str | bool]]:
    checks: list[dict[str, str | bool]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    add(
        "Alertas",
        alert_configured(),
        f"provedor={ALERT_PROVIDER}",
    )
    configured_env = next((path for path in ENV_PATHS if path.exists()), None)
    add(
        "Configuração",
        configured_env is not None,
        str(configured_env) if configured_env else "arquivo .env não encontrado",
    )
    if configured_env:
        is_link = configured_env.is_symlink()
        info = configured_env.stat()
        mode = info.st_mode & 0o777
        allowed_uids = {0, os.getuid()}
        target_user = os.environ.get("KALI_BUNKER_USER", "").strip()
        if target_user:
            try:
                allowed_uids.add(pwd.getpwnam(target_user).pw_uid)
            except KeyError:
                pass
        add("Arquivo .env regular", not is_link, "ok" if not is_link else "link simbólico recusado")
        add("Proprietário do .env", info.st_uid in allowed_uids, f"uid={info.st_uid}")
        add("Permissões do .env", mode == 0o600, f"modo={mode:03o}; exigido=600")

    integrity = verify_runtime_integrity()
    add("Integridade do runtime", bool(integrity["ok"]), describe_integrity(integrity))

    protected = Path(PROTECTED_DIR).expanduser()
    add("Diretório protegido", protected.is_dir(), str(protected))
    known_macs = Path(KNOWN_MACS_FILE).expanduser()
    add("Base de MACs", known_macs.exists(), str(known_macs))
    add("Bluetooth configurado", bool(IPHONE_MAC), IPHONE_MAC or "IPHONE_MAC vazio")
    interface_exists = Path(f"/sys/class/net/{WIFI_INTERFACE}").exists()
    add("Interface Wi-Fi", interface_exists, WIFI_INTERFACE)

    for command in REQUIRED_COMMANDS:
        path = shutil.which(command)
        add(f"Comando {command}", path is not None, path or "não instalado")

    can_query_systemd = systemd_accessible()
    add(
        "Acesso ao systemd",
        can_query_systemd,
        "ok" if can_query_systemd else "systemctl indisponível neste contexto",
    )
    if not can_query_systemd:
        return checks

    for spec in SERVICES:
        state = service_state(spec.unit)
        ok = (
            state == "active"
            or (spec.inactive_ok and state == "inactive")
            or (not spec.critical and state in {"inactive", "not-found", "unknown"})
        )
        add(f"Serviço {spec.unit}", ok, state)

    return checks
