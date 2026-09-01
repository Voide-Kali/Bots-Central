#!/usr/bin/env python3
"""CLI operacional do Kali Bunker."""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from bunker_audit import AUDIT_LOG, STATE_DIR, record_event
from bunker_health import SERVICES, collect_health, doctor_checks
from bunker_config import (
    BANNED_DEVICES_FILE,
    ENV_PATHS,
    KNOWN_MACS_FILE,
    OPERATIONAL_HOME,
    PROJECT_DIR,
    PROTECTED_DIR,
    WIFI_INTERFACE,
)
from notifier import alert_config_error, alert_configured, send_alert
from runtime_integrity import describe_integrity


console = Console()
SAFE_BACKUP_ENV_KEYS = frozenset(
    {
        "ALERT_PROVIDER",
        "WIFI_INTERFACE",
        "PROTECTED_DIR",
        "RSSI_LIMITE",
        "INTERVALO_BLUETOOTH",
        "FALHAS_MAX",
        "LIMITE_CPU",
        "LIMITE_RAM",
        "INTERVALO_RECURSOS",
        "COOLDOWN_RECURSOS",
        "NETWORK_SCAN_TIMEOUT_SECONDS",
        "TELEGRAM_POLL_INTERVAL_SECONDS",
    }
)
DEFAULT_BACKUP_DIR = STATE_DIR / "backups"
BANLIST_FILE = Path(BANNED_DEVICES_FILE).expanduser()
MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
NMAP_REPORT_RE = re.compile(r"^Nmap scan report for (?P<target>.+)$")
NMAP_MAC_RE = re.compile(
    r"^MAC Address:\s+(?P<mac>(?:[0-9A-F]{2}:){5}[0-9A-F]{2})(?:\s+\((?P<vendor>.*)\))?$",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    entrypoint: str
    description: str
    service: str | None = None


TOOLS = (
    ToolSpec("bunkerctl", "operacao", "bunkerctl.py", "CLI operacional, diagnostico, reparo, backup e auditoria"),
    ToolSpec("bunker-dashboard", "operacao", "dashboard.py", "Dashboard terminal em tempo real"),
    ToolSpec("bluetooth-alarm", "sensor", "bluetooth_alarm.py", "Alarme de proximidade Bluetooth e bloqueio USB/tela", "bt-alarm.service"),
    ToolSpec("auth-monitor", "sensor", "monitor-auth.py", "Detector de tentativas de login com captura de webcam", "monitor-auth.service"),
    ToolSpec("resource-monitor", "sensor", "monitor-recursos.py", "Monitor de CPU, RAM e processos pesados", "monitor-recursos.service"),
    ToolSpec("wifi-monitor", "sensor", "monitor-wifi.py", "Detector de dispositivos desconhecidos na rede", "monitor-wifi.service"),
    ToolSpec("network-ban", "resposta", "bunkerctl ban", "Bloqueio defensivo local de IPs e MACs suspeitos"),
    ToolSpec("telegram-network", "resposta", "telegram_control.py", "Controle de scan e bloqueio de rede pelo Telegram", "kali-bunker-telegram.service"),
    ToolSpec("network-watch", "sensor", "network-watch.sh", "Reaprendizado de rede quando SSID/gateway mudam", "network-watch.service"),
    ToolSpec("file-monitor", "sensor", "monitor-arquivos.sh", "Monitor de arquivos sensiveis com inotify", "monitor-arquivos.service"),
    ToolSpec("health-monitor", "watchdog", "health_monitor.py", "Autovigilancia dos servicos do Kali Bunker", "kali-bunker-health.service"),
    ToolSpec("weekly-cleanup", "manutencao", "limpeza-semanal.sh", "Limpeza semanal de cache e pacotes", "limpeza-semanal.timer"),
    ToolSpec("weekly-report", "manutencao", "relatorio-semanal.sh", "Relatorio semanal de saude", "relatorio-semanal.timer"),
    ToolSpec("boot-alert", "notificacao", "notifica_boot.py", "Notificacao de boot", "notifica-boot.service"),
    ToolSpec("shutdown-alert", "notificacao", "notifica_shutdown.py", "Notificacao de desligamento", "notifica-shutdown.service"),
)

CORE_SERVICE_UNITS = tuple(spec.unit for spec in SERVICES if spec.critical)
QUICK_COMMANDS = (
    ("kb overview", "visao curta do estado geral"),
    ("sudo kb up", "liga os modulos principais"),
    ("sudo kb down", "desliga os modulos principais"),
    ("sudo kb restart", "reinicia os modulos principais"),
    ("kb doctor", "diagnostico completo"),
    ("kb network scan --unknown-only", "mostra dispositivos desconhecidos"),
    ("kb ban list", "lista bloqueios"),
    ("kb backup --keep 10", "backup operacional"),
)


def run_system(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def command_status(as_json: bool) -> int:
    report = collect_health()
    if as_json:
        console.print_json(json.dumps(report, ensure_ascii=False))
        return 0 if report["healthy"] else 1

    resources = report["resources"]
    console.print(
        f"[bold bright_blue]Kali Bunker[/] · {report['host']} · "
        f"{'SAUDÁVEL' if report['healthy'] else 'ATENÇÃO'}"
    )
    console.print(
        f"CPU {resources['cpu_percent']:.1f}% · "
        f"RAM {resources['memory_percent']:.1f}% · "
        f"Disco {resources['disk_percent']:.1f}% · "
        f"Livres {resources['disk_free_gib']:.1f} GiB"
    )
    integrity = report.get("runtime_integrity")
    if isinstance(integrity, dict):
        style = "bright_green" if integrity.get("ok") else "bright_red"
        console.print(
            f"Runtime SHA-256: [{style}]"
            f"{'OK' if integrity.get('ok') else 'FALHA'}[/] · "
            f"{describe_integrity(integrity)}"
        )
    table = Table(box=box.SIMPLE, header_style="bold")
    table.add_column("Unidade")
    table.add_column("Estado")
    table.add_column("Inicialização")
    table.add_column("Criticidade")
    for item in report["services"]:
        style = "bright_green" if item["state"] == "active" else "bright_red"
        table.add_row(
            item["unit"],
            f"[{style}]{item['state']}[/]",
            item["enabled"],
            "crítica" if item["critical"] else "opcional",
        )
    console.print(table)
    return 0 if report["healthy"] else 1


def command_doctor(as_json: bool, fix: bool = False) -> int:
    checks = doctor_checks()
    if as_json:
        console.print_json(json.dumps(checks, ensure_ascii=False))
    else:
        table = Table(title="Diagnóstico do Kali Bunker", box=box.ROUNDED)
        table.add_column("Resultado", width=10)
        table.add_column("Verificação")
        table.add_column("Detalhes")
        for check in checks:
            ok = bool(check["ok"])
            table.add_row(
                "[bright_green]OK[/]" if ok else "[bright_red]FALHA[/]",
                str(check["name"]),
                str(check["detail"]),
            )
        console.print(table)

    if fix:
        console.print()
        command_repair(apply=True, quiet=False)
    return 0 if all(bool(check["ok"]) for check in checks) else 1


def command_alert_test() -> int:
    if not alert_configured():
        console.print(f"[red]{alert_config_error()}[/]")
        return 2
    sent = send_alert(
        "✅ KALI BUNKER",
        "Teste operacional concluído com sucesso pelo bunkerctl.",
    )
    console.print("[green]Alerta enviado.[/]" if sent else "[red]Falha no envio.[/]")
    return 0 if sent else 1


def command_tools(category: str | None, as_json: bool) -> int:
    tools = [tool for tool in TOOLS if not category or tool.category == category]
    if as_json:
        console.print_json(json.dumps([asdict(tool) for tool in tools], ensure_ascii=False))
        return 0
    if not tools:
        console.print(f"[red]Categoria nao encontrada:[/] {category}")
        return 2

    table = Table(title="Ferramentas do Kali Bunker", box=box.ROUNDED)
    table.add_column("Ferramenta", style="bold bright_cyan")
    table.add_column("Categoria")
    table.add_column("Entrada")
    table.add_column("Servico")
    table.add_column("Descricao")
    for tool in tools:
        table.add_row(
            tool.name,
            tool.category,
            tool.entrypoint,
            tool.service or "-",
            tool.description,
        )
    console.print(table)
    return 0


def command_logs(unit: str, lines: int) -> int:
    allowed = {spec.unit for spec in SERVICES}
    if unit not in allowed:
        console.print(f"[red]Unidade não reconhecida: {unit}[/]")
        return 2
    result = subprocess.run(
        ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"],
        check=False,
    )
    return result.returncode


def read_audit_entries(lines: int | None = None) -> list[dict]:
    if not AUDIT_LOG.exists():
        return []
    raw_entries = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
    if lines:
        raw_entries = raw_entries[-lines:]
    entries = []
    for entry in raw_entries:
        try:
            entries.append(json.loads(entry))
        except json.JSONDecodeError:
            entries.append({"raw": entry})
    return entries


def csv_safe_cell(value: object) -> str:
    """Neutraliza fórmulas ao abrir exportações em Excel/Calc."""
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    candidate = text.lstrip(" \t\r\n")
    if candidate.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def command_audit(lines: int, export_format: str | None = None, output: str | None = None) -> int:
    entries = read_audit_entries(lines)
    if not entries:
        console.print("Nenhum evento de auditoria registrado.")
        return 0

    if export_format:
        target = Path(output).expanduser() if output else Path(f"audit-export.{export_format}")
        target.parent.mkdir(parents=True, exist_ok=True)
        if export_format == "json":
            target.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
        elif export_format == "jsonl":
            target.write_text(
                "\n".join(json.dumps(item, ensure_ascii=False) for item in entries) + "\n",
                encoding="utf-8",
            )
        elif export_format == "csv":
            keys = sorted({key for item in entries for key in item.keys()})
            with target.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=keys)
                writer.writeheader()
                writer.writerows(
                    {key: csv_safe_cell(item.get(key, "")) for key in keys}
                    for item in entries
                )
        console.print(f"Auditoria exportada para [bold]{target}[/].")
        record_event("audit_export", format=export_format, output=str(target), entries=len(entries))
        return 0

    for entry in entries:
        try:
            console.print_json(json.dumps(entry, ensure_ascii=False))
        except Exception:
            console.print(entry)
    return 0


def format_duration(seconds: int) -> str:
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}min")
    return " ".join(parts)


def report_payload(audit_lines: int = 10) -> dict:
    return {
        "health": collect_health(),
        "checks": doctor_checks(),
        "audit": read_audit_entries(audit_lines),
    }


def render_report_text(payload: dict) -> str:
    health = payload["health"]
    resources = health["resources"]
    checks = payload["checks"]
    failed_checks = [check for check in checks if not check["ok"]]
    lines = [
        "Kali Bunker Report",
        f"Gerado em: {health['generated_at']}",
        f"Host: {health['host']}",
        f"Estado: {'SAUDAVEL' if health['healthy'] else 'ATENCAO'}",
        f"Uptime: {format_duration(int(health['uptime_seconds']))}",
        "",
        "Recursos",
        f"- CPU: {resources['cpu_percent']:.1f}%",
        f"- RAM: {resources['memory_percent']:.1f}%",
        f"- Disco: {resources['disk_percent']:.1f}% ({resources['disk_free_gib']} GiB livres)",
        f"- Load: {resources['load_1m']} / {resources['load_5m']} / {resources['load_15m']}",
        f"- Temperatura: {resources['temperature_c'] if resources['temperature_c'] is not None else 'indisponivel'}",
        "",
        "Servicos",
    ]
    for service in health["services"]:
        critical = "critico" if service["critical"] else "opcional"
        lines.append(f"- {service['unit']}: {service['state']} / {service['enabled']} ({critical})")
    lines.extend(["", "Diagnostico"])
    if failed_checks:
        for check in failed_checks:
            lines.append(f"- FALHA: {check['name']} - {check['detail']}")
    else:
        lines.append("- Todos os checks passaram.")
    lines.extend(["", "Eventos recentes"])
    if payload["audit"]:
        for event in payload["audit"]:
            lines.append(f"- {event.get('timestamp', '-')}: {event.get('event', event.get('raw', '-'))}")
    else:
        lines.append("- Nenhum evento registrado.")
    return "\n".join(lines) + "\n"


def render_report_html(payload: dict) -> str:
    health = payload["health"]
    resources = health["resources"]
    checks = payload["checks"]
    audit = payload["audit"]
    status_class = "ok" if health["healthy"] else "warn"

    def esc(value: object) -> str:
        return html.escape(str(value))

    service_rows = "\n".join(
        "<tr>"
        f"<td>{esc(service['unit'])}</td>"
        f"<td>{esc(service['state'])}</td>"
        f"<td>{esc(service['enabled'])}</td>"
        f"<td>{'critico' if service['critical'] else 'opcional'}</td>"
        "</tr>"
        for service in health["services"]
    )
    check_rows = "\n".join(
        "<tr>"
        f"<td>{'OK' if check['ok'] else 'FALHA'}</td>"
        f"<td>{esc(check['name'])}</td>"
        f"<td>{esc(check['detail'])}</td>"
        "</tr>"
        for check in checks
    )
    audit_rows = "\n".join(
        "<tr>"
        f"<td>{esc(event.get('timestamp', '-'))}</td>"
        f"<td>{esc(event.get('event', event.get('raw', '-')))}</td>"
        "</tr>"
        for event in audit
    ) or '<tr><td colspan="2">Nenhum evento registrado.</td></tr>'
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Kali Bunker Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ color: #102a43; }}
    .status {{ display: inline-block; padding: 6px 10px; border-radius: 4px; font-weight: bold; }}
    .ok {{ background: #d9fbe6; color: #0b6b3a; }}
    .warn {{ background: #fff3c4; color: #8a4b00; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 28px; }}
    th, td {{ border: 1px solid #d9e2ec; padding: 8px; text-align: left; }}
    th {{ background: #f0f4f8; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .metric {{ border: 1px solid #d9e2ec; padding: 12px; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>Kali Bunker Report</h1>
  <p><span class="status {status_class}">{'SAUDAVEL' if health['healthy'] else 'ATENCAO'}</span></p>
  <p><strong>Host:</strong> {esc(health['host'])}<br>
  <strong>Gerado em:</strong> {esc(health['generated_at'])}<br>
  <strong>Uptime:</strong> {esc(format_duration(int(health['uptime_seconds'])))}</p>

  <h2>Recursos</h2>
  <div class="grid">
    <div class="metric">CPU: {resources['cpu_percent']:.1f}%</div>
    <div class="metric">RAM: {resources['memory_percent']:.1f}%</div>
    <div class="metric">Disco: {resources['disk_percent']:.1f}%</div>
    <div class="metric">Livres: {resources['disk_free_gib']} GiB</div>
  </div>

  <h2>Servicos</h2>
  <table><thead><tr><th>Unidade</th><th>Estado</th><th>Inicializacao</th><th>Tipo</th></tr></thead><tbody>
  {service_rows}
  </tbody></table>

  <h2>Diagnostico</h2>
  <table><thead><tr><th>Resultado</th><th>Check</th><th>Detalhe</th></tr></thead><tbody>
  {check_rows}
  </tbody></table>

  <h2>Eventos recentes</h2>
  <table><thead><tr><th>Data</th><th>Evento</th></tr></thead><tbody>
  {audit_rows}
  </tbody></table>
</body>
</html>
"""


def command_report(report_format: str, output: str | None, audit_lines: int) -> int:
    payload = report_payload(audit_lines)
    if report_format == "json":
        content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    elif report_format == "html":
        content = render_report_html(payload)
    else:
        content = render_report_text(payload)

    if output:
        target = Path(output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        console.print(f"Relatorio criado em [bold]{target}[/].")
        record_event("report", format=report_format, output=str(target))
        return 0

    if report_format == "json":
        console.print_json(content)
    else:
        console.print(content)
    record_event("report", format=report_format, output=None)
    return 0


def normalize_mac(value: str) -> str:
    mac = value.strip().replace("-", ":").upper()
    if not MAC_RE.fullmatch(mac):
        raise ValueError(f"MAC invalido: {value}")
    return mac


def normalize_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"IP invalido: {value}") from exc
    if address.version != 4:
        raise ValueError("Apenas IPv4 e suportado nesta ferramenta.")
    return str(address)


def normalize_scan_target(value: str) -> str:
    """Aceita somente IPv4/CIDR local; nunca encaminha opções ao scanner."""
    target = value.strip()
    if not target or target.startswith("-") or any(char.isspace() for char in target):
        raise ValueError("Alvo de scan invalido.")
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ValueError(f"Alvo de scan invalido: {value}") from exc
    if network.version != 4:
        raise ValueError("Apenas redes IPv4 sao permitidas.")
    if not (network.is_private or network.is_loopback or network.is_link_local):
        raise ValueError("O scan aceita somente enderecos privados ou locais.")
    return str(network.network_address) if network.prefixlen == 32 else str(network)


def operational_owner_ids() -> tuple[int, int] | None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return None
    try:
        owner = OPERATIONAL_HOME.resolve(strict=True).stat()
    except OSError:
        return None
    if owner.st_uid == 0:
        return None
    return owner.st_uid, owner.st_gid


def chown_operational(path: Path) -> None:
    owner = operational_owner_ids()
    if not owner:
        return
    try:
        os.chown(path, owner[0], owner[1])
    except PermissionError:
        return


def normalize_saved_file_owner(path: Path, mode: int) -> None:
    os.chmod(path, mode)
    chown_operational(path)


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Grava no mesmo filesystem com nome imprevisível e troca atômica."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            os.chmod(stream.name, mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        normalize_saved_file_owner(path, mode)
    finally:
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def parse_nmap_target(value: str) -> tuple[str | None, str]:
    target = value.strip()
    match = re.search(r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)$", target)
    if match:
        try:
            ip = normalize_ip(match.group("ip"))
        except ValueError:
            return None, "N/D"
        hostname = target[: match.start()].strip() or "N/D"
        return ip, hostname

    match = IPV4_RE.search(target)
    if not match:
        return None, target or "N/D"
    try:
        ip = normalize_ip(match.group(0))
    except ValueError:
        return None, target or "N/D"
    hostname = "N/D" if target == ip else target.replace(ip, "").strip(" ()") or "N/D"
    return ip, hostname


def parse_nmap_scan(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in output.splitlines():
        report_match = NMAP_REPORT_RE.match(line.strip())
        if report_match:
            if current and current.get("ip"):
                devices.append(current)
            ip, hostname = parse_nmap_target(report_match.group("target"))
            current = {
                "ip": ip or "",
                "hostname": hostname,
                "mac": "",
                "vendor": "N/D",
            }
            continue

        mac_match = NMAP_MAC_RE.match(line.strip())
        if current is not None and mac_match:
            current["mac"] = normalize_mac(mac_match.group("mac"))
            current["vendor"] = (mac_match.group("vendor") or "N/D").strip()

    if current and current.get("ip"):
        devices.append(current)
    return devices


def parse_arp_scan(output: str) -> list[dict[str, str]]:
    devices = []
    for line in output.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            ip = normalize_ip(parts[0])
            mac = normalize_mac(parts[1])
        except ValueError:
            continue
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": "N/D",
                "vendor": parts[2].strip() if len(parts) > 2 else "N/D",
            }
        )
    return devices


def default_route_interface() -> str | None:
    route = run_system(["ip", "route", "get", "1.1.1.1"])
    if route.returncode == 0:
        parts = route.stdout.split()
        if "dev" in parts:
            index = parts.index("dev")
            if index + 1 < len(parts):
                return parts[index + 1]

    default_route = run_system(["ip", "route", "show", "default"])
    if default_route.returncode != 0:
        return None
    for line in default_route.stdout.splitlines():
        parts = line.split()
        if parts[:1] == ["default"] and "dev" in parts:
            index = parts.index("dev")
            if index + 1 < len(parts):
                return parts[index + 1]
    return None


def active_ipv4_networks() -> list[tuple[str, str]]:
    result = run_system(["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"])
    if result.returncode != 0:
        return []

    candidates = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        interface = parts[1]
        try:
            network = ipaddress.ip_interface(parts[3]).network
        except ValueError:
            continue
        candidates.append((interface, str(network)))
    return candidates


def hostname_ipv4_networks() -> list[tuple[str, str]]:
    result = run_system(["hostname", "-I"])
    if result.returncode != 0:
        return []
    networks = []
    for raw_ip in result.stdout.split():
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if address.version != 4:
            continue
        network = ipaddress.ip_network(f"{address}/24", strict=False)
        networks.append(("hostname", str(network)))
    return networks


def default_scan_target() -> str:
    candidates = active_ipv4_networks()
    default_interface = default_route_interface()
    if candidates and default_interface:
        for interface, network in candidates:
            if interface == default_interface:
                return network

    if candidates:
        for interface, network in candidates:
            if interface == WIFI_INTERFACE:
                return network
        return candidates[0][1]

    hostname_candidates = hostname_ipv4_networks()
    if hostname_candidates:
        return hostname_candidates[0][1]

    configured = str(os.environ.get("NETWORK_SCAN_TARGET", "")).strip()
    if configured:
        try:
            network = ipaddress.ip_network(configured, strict=False)
        except ValueError:
            network = None
        if network and network.prefixlen < 32 and (network.is_private or network.is_loopback or network.is_link_local):
            return str(network)

    raise RuntimeError(
        "Nao foi possivel detectar uma rede local. "
        "Conecte a rede ou configure NETWORK_SCAN_TARGET no .env."
    )


def scan_network_devices(target: str | None = None) -> list[dict[str, str]]:
    scan_target = normalize_scan_target(target or default_scan_target())
    errors = []

    nmap = shutil.which("nmap")
    if nmap:
        result = run_system([nmap, "-sn", scan_target], timeout=120)
        if result.returncode == 0:
            return parse_nmap_scan(result.stdout)
        errors.append((result.stderr or result.stdout).strip() or "nmap falhou ao escanear a rede.")

    arp_scan = shutil.which("arp-scan")
    if arp_scan:
        command = [arp_scan, "--ignoredups"]
        command.append(scan_target)
        if WIFI_INTERFACE:
            command.insert(1, f"--interface={WIFI_INTERFACE}")
        if os.geteuid() != 0 and shutil.which("sudo"):
            command = ["sudo", "-n", *command]
        result = run_system(command, timeout=60)
        if result.returncode == 0:
            return parse_arp_scan(result.stdout)
        errors.append((result.stderr or result.stdout).strip() or "arp-scan falhou ao escanear a rede.")

    if errors:
        raise RuntimeError(" | ".join(errors))

    raise RuntimeError("Instale nmap ou arp-scan para usar os comandos de rede.")


def save_known_macs(macs: set[str]) -> None:
    path = Path(KNOWN_MACS_FILE).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    normalize_saved_file_owner(path.parent, 0o700)
    atomic_write_text(path, "\n".join(sorted(macs)) + ("\n" if macs else ""), 0o600)


def network_gateway() -> str:
    result = run_system(["ip", "route", "show", "default"])
    if result.returncode != 0:
        return "N/D"
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts[:1] == ["default"] and "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts):
                return parts[index + 1]
    return "N/D"


def network_ssid() -> str:
    if not WIFI_INTERFACE:
        return "N/D"
    result = run_system(["iwgetid", "-r", "-i", WIFI_INTERFACE], timeout=5)
    if result.returncode != 0:
        return "N/D"
    return result.stdout.strip() or "N/D"


def load_known_macs() -> set[str]:
    known: set[str] = set()
    path = Path(KNOWN_MACS_FILE).expanduser()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                known.add(normalize_mac(line))
            except ValueError:
                continue
    for mac in os.environ.get("ALLOWED_MACS", "").split(","):
        try:
            known.add(normalize_mac(mac))
        except ValueError:
            continue
    return known


def annotate_devices(devices: list[dict[str, str]]) -> list[dict[str, str]]:
    known_macs = load_known_macs()
    bans = load_banlist()
    banned_ips = {str(item.get("value")) for item in bans if item.get("type") == "ip"}
    banned_macs = {str(item.get("value")) for item in bans if item.get("type") == "mac"}
    annotated = []
    for index, device in enumerate(devices, start=1):
        item = dict(device)
        mac = item.get("mac", "")
        item["index"] = str(index)
        item["known"] = "yes" if mac and mac in known_macs else "no"
        item["banned"] = "yes" if item.get("ip") in banned_ips or (mac and mac in banned_macs) else "no"
        annotated.append(item)
    return annotated


def render_scan_table(devices: list[dict[str, str]]) -> None:
    table = Table(title="Dispositivos encontrados na rede", box=box.ROUNDED)
    table.add_column("#", justify="right")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Hostname")
    table.add_column("Fabricante")
    table.add_column("Status")
    for device in devices:
        if device["banned"] == "yes":
            status = "[yellow]banido[/]"
        elif device["known"] == "yes":
            status = "[green]conhecido[/]"
        else:
            status = "[red]desconhecido[/]"
        table.add_row(
            device["index"],
            device.get("ip", "-"),
            device.get("mac") or "-",
            device.get("hostname") or "N/D",
            device.get("vendor") or "N/D",
            status,
        )
    console.print(table)


def select_scanned_device(
    devices: list[dict[str, str]],
    selected_index: int | None = None,
    selected_ip: str | None = None,
    selected_mac: str | None = None,
) -> dict[str, str] | None:
    if selected_index is not None:
        for device in devices:
            if int(device["index"]) == selected_index:
                return device
        return None

    if selected_ip:
        ip = normalize_ip(selected_ip)
        return next((device for device in devices if device.get("ip") == ip), None)

    if selected_mac:
        mac = normalize_mac(selected_mac)
        return next((device for device in devices if device.get("mac") == mac), None)

    return None


def add_ban_record(kind: str, value: str, reason: str) -> tuple[str, bool]:
    normalized = normalize_ip(value) if kind == "ip" else normalize_mac(value)
    bans = load_banlist()
    record = {
        "type": kind,
        "value": normalized,
        "reason": reason,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    existing_keys = {ban_key(item) for item in bans if "type" in item and "value" in item}
    created = ban_key(record) not in existing_keys
    if created:
        bans.append(record)
        save_banlist(bans)
    return normalized, created


def load_banlist() -> list[dict[str, object]]:
    if not BANLIST_FILE.exists():
        return []
    try:
        data = json.loads(BANLIST_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def save_banlist(items: list[dict[str, object]]) -> None:
    BANLIST_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    normalize_saved_file_owner(BANLIST_FILE.parent, 0o700)
    atomic_write_text(BANLIST_FILE, json.dumps(items, ensure_ascii=False, indent=2), 0o600)


def ban_key(item: dict[str, object]) -> tuple[str, str]:
    return str(item["type"]), str(item["value"])


def ban_firewall_commands(kind: str, value: str, remove: bool = False) -> list[list[str]]:
    if kind == "ip":
        rule_sets = (
            ["INPUT", "-s", value, "-j", "DROP"],
            ["OUTPUT", "-d", value, "-j", "DROP"],
            ["FORWARD", "-s", value, "-j", "DROP"],
            ["FORWARD", "-d", value, "-j", "DROP"],
        )
    elif kind == "mac":
        rule_sets = (
            ["INPUT", "-m", "mac", "--mac-source", value, "-j", "DROP"],
            ["FORWARD", "-m", "mac", "--mac-source", value, "-j", "DROP"],
        )
    else:
        raise ValueError(f"Tipo de bloqueio invalido: {kind}")

    action = "-D" if remove else "-A"
    return [["iptables", action, *rule] for rule in rule_sets]


def rule_exists(command: list[str]) -> bool:
    check_command = [command[0], "-C", *command[2:]]
    return run_system(check_command).returncode == 0


def apply_ban_rules(kind: str, value: str) -> tuple[int, list[str]]:
    failures = 0
    messages = []
    for command in ban_firewall_commands(kind, value):
        if rule_exists(command):
            messages.append(f"ja existe: {' '.join(command[2:])}")
            continue
        exec_command = command
        if os.geteuid() != 0 and shutil.which("sudo"):
            exec_command = ["sudo", "-n", *command]
        result = run_system(exec_command)
        if result.returncode == 0:
            messages.append(f"aplicada: {' '.join(command[2:])}")
        else:
            failures += 1
            messages.append((result.stderr or result.stdout).strip() or f"falha: {' '.join(command)}")
    return failures, messages


def notify_network_ban(
    action: str,
    targets: list[tuple[str, str]],
    reason: str,
    applied: bool,
    failures: int,
) -> bool | None:
    if not alert_configured():
        return None

    target_lines = "\n".join(f"- {kind}: {value}" for kind, value in targets)
    status = "aplicado no firewall local" if applied and failures == 0 else "registrado na lista local"
    if failures:
        status = f"com {failures} falha(s) ao aplicar firewall"
    sent = send_alert(
        "🛡️ KALI BUNKER - BLOQUEIO DE REDE",
        (
            f"Acao: {action}\n"
            f"Status: {status}\n"
            f"Motivo: {reason}\n"
            "Alvos:\n"
            f"{target_lines}"
        ),
        sound="siren",
    )
    console.print("[green]Alerta enviado.[/]" if sent else "[red]Falha no envio do alerta.[/]")
    return sent


def remove_ban_rules(kind: str, value: str) -> tuple[int, list[str]]:
    failures = 0
    messages = []
    for command in ban_firewall_commands(kind, value, remove=True):
        add_command = [command[0], "-A", *command[2:]]
        if not rule_exists(add_command):
            messages.append(f"ausente: {' '.join(command[2:])}")
            continue
        exec_command = command
        if os.geteuid() != 0 and shutil.which("sudo"):
            exec_command = ["sudo", "-n", *command]
        result = run_system(exec_command)
        if result.returncode == 0:
            messages.append(f"removida: {' '.join(command[2:])}")
        else:
            failures += 1
            messages.append((result.stderr or result.stdout).strip() or f"falha: {' '.join(command)}")
    return failures, messages


def command_ban_list(as_json: bool) -> int:
    bans = load_banlist()
    if as_json:
        console.print_json(json.dumps(bans, ensure_ascii=False))
        return 0
    if not bans:
        console.print("Nenhum dispositivo banido.")
        return 0
    table = Table(title="Dispositivos banidos", box=box.ROUNDED)
    table.add_column("Tipo")
    table.add_column("Valor")
    table.add_column("Motivo")
    table.add_column("Criado em")
    for item in bans:
        table.add_row(
            str(item.get("type", "-")),
            str(item.get("value", "-")),
            str(item.get("reason", "-")),
            str(item.get("created_at", "-")),
        )
    console.print(table)
    return 0


def command_ban_add(kind: str, value: str, reason: str, apply_rules: bool) -> int:
    normalized, created = add_ban_record(kind, value, reason)
    failures = 0
    if apply_rules:
        failures, messages = apply_ban_rules(kind, normalized)
        for message in messages:
            console.print(f"- {message}")
    console.print(f"Ban {'registrado' if created else 'ja existente'}: {kind} {normalized}")
    if not apply_rules:
        console.print("Use --apply para aplicar regras locais de firewall agora.")
    notify_network_ban("ban registrado", [(kind, normalized)], reason, apply_rules, failures)
    record_event("network_ban_add", type=kind, value=normalized, reason=reason, applied=apply_rules, failures=failures)
    return 0 if failures == 0 else 1


def command_ban_remove(kind: str, value: str, apply_rules: bool) -> int:
    normalized = normalize_ip(value) if kind == "ip" else normalize_mac(value)
    bans = load_banlist()
    filtered = [
        item
        for item in bans
        if item.get("type") != kind or item.get("value") != normalized
    ]
    save_banlist(filtered)
    failures = 0
    if apply_rules:
        failures, messages = remove_ban_rules(kind, normalized)
        for message in messages:
            console.print(f"- {message}")
    console.print(f"Ban removido: {kind} {normalized}")
    notify_network_ban("ban removido", [(kind, normalized)], "remocao manual", apply_rules, failures)
    record_event("network_ban_remove", type=kind, value=normalized, applied=apply_rules, failures=failures)
    return 0 if failures == 0 else 1


def command_ban_apply() -> int:
    failures = 0
    for item in load_banlist():
        kind = str(item.get("type", ""))
        value = str(item.get("value", ""))
        if kind not in {"ip", "mac"} or not value:
            continue
        item_failures, messages = apply_ban_rules(kind, value)
        failures += item_failures
        console.print(f"[bold]{kind} {value}[/]")
        for message in messages:
            console.print(f"- {message}")
    record_event("network_ban_apply", failures=failures)
    return 0 if failures == 0 else 1


def command_network_status(as_json: bool) -> int:
    scanner = shutil.which("nmap") or shutil.which("arp-scan")
    try:
        target = default_scan_target()
    except RuntimeError as exc:
        target = f"erro: {exc}"

    payload = {
        "interface": WIFI_INTERFACE or "N/D",
        "default_interface": default_route_interface() or "N/D",
        "ssid": network_ssid(),
        "gateway": network_gateway(),
        "scan_target": target,
        "scanner": scanner or "",
        "known_macs": len(load_known_macs()),
        "banned_devices": len(load_banlist()),
    }

    if as_json:
        console.print_json(json.dumps(payload, ensure_ascii=False))
        return 0

    table = Table(title="Rede Kali Bunker", box=box.ROUNDED)
    table.add_column("Item")
    table.add_column("Valor")
    labels = {
        "interface": "Interface configurada",
        "default_interface": "Interface da rota padrao",
        "ssid": "SSID",
        "gateway": "Gateway",
        "scan_target": "Alvo automatico",
        "scanner": "Scanner",
        "known_macs": "MACs conhecidos",
        "banned_devices": "Dispositivos banidos",
    }
    for key, label in labels.items():
        table.add_row(label, str(payload[key] or "PENDENTE"))
    console.print(table)
    return 0 if scanner else 1


def command_network_scan(target: str | None, unknown_only: bool, as_json: bool) -> int:
    try:
        devices = annotate_devices(scan_network_devices(target))
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    if unknown_only:
        devices = [device for device in devices if device["known"] != "yes"]

    if as_json:
        console.print_json(json.dumps(devices, ensure_ascii=False))
        return 0

    if not devices:
        console.print("Nenhum dispositivo encontrado no scan.")
        return 0
    render_scan_table(devices)
    return 0


def command_network_learn(target: str | None, replace: bool, as_json: bool) -> int:
    try:
        devices = scan_network_devices(target)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    scanned_macs = {
        normalize_mac(device["mac"])
        for device in devices
        if device.get("mac")
    }
    previous_macs = set() if replace else load_known_macs()
    learned_macs = previous_macs | scanned_macs
    save_known_macs(learned_macs)
    record_event(
        "network_learn",
        target=target or "auto",
        scanned=len(devices),
        learned=len(scanned_macs),
        total=len(learned_macs),
        replace=replace,
    )

    payload = {
        "scanned_devices": len(devices),
        "learned_macs": len(scanned_macs),
        "total_known_macs": len(learned_macs),
        "file": str(Path(KNOWN_MACS_FILE).expanduser()),
    }
    if as_json:
        console.print_json(json.dumps(payload, ensure_ascii=False))
        return 0

    console.print(
        f"[green]Rede aprendida.[/] {payload['learned_macs']} MAC(s) do scan, "
        f"{payload['total_known_macs']} conhecido(s) no total."
    )
    console.print(f"Arquivo: {payload['file']}")
    console.print("Reinicie monitor-wifi.service para usar a lista atualizada imediatamente.")
    return 0


def command_ban_scan(
    target: str | None,
    apply_rules: bool,
    unknown_only: bool,
    as_json: bool,
    selected_index: int | None,
    selected_ip: str | None,
    selected_mac: str | None,
    reason: str,
) -> int:
    if selected_index is not None and selected_index < 1:
        console.print("[red]O numero selecionado precisa ser 1 ou maior.[/]")
        return 2

    try:
        devices = annotate_devices(scan_network_devices(target))
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    if unknown_only:
        devices = [device for device in devices if device["known"] != "yes"]

    if as_json:
        console.print_json(json.dumps(devices, ensure_ascii=False))
        return 0

    if not devices:
        console.print("Nenhum dispositivo encontrado no scan.")
        return 1

    render_scan_table(devices)
    selected = select_scanned_device(devices, selected_index, selected_ip, selected_mac)
    selection_requested = selected_index is not None or selected_ip is not None or selected_mac is not None

    if selected is None and not selection_requested:
        if not sys.stdin.isatty():
            console.print("Use --select NUMERO, --ip IP ou --mac MAC para escolher o dispositivo.")
            return 0
        answer = console.input("Digite o numero do dispositivo para banir, ou Enter para cancelar: ").strip()
        if not answer:
            console.print("Operacao cancelada.")
            return 0
        try:
            selected = select_scanned_device(devices, selected_index=int(answer))
        except ValueError:
            console.print("[red]Numero invalido.[/]")
            return 2

    if selected is None:
        console.print("[red]Dispositivo selecionado nao foi encontrado no scan.[/]")
        return 2

    targets = [("ip", selected["ip"])]
    if selected.get("mac"):
        targets.append(("mac", selected["mac"]))

    failures = 0
    normalized_targets: list[tuple[str, str]] = []
    console.print(f"Alvo selecionado: IP {selected['ip']} MAC {selected.get('mac') or 'N/D'}")
    for kind, value in targets:
        normalized, created = add_ban_record(kind, value, reason)
        normalized_targets.append((kind, normalized))
        if apply_rules:
            item_failures, messages = apply_ban_rules(kind, normalized)
            failures += item_failures
            for message in messages:
                console.print(f"- {message}")
        console.print(f"Ban {'registrado' if created else 'ja existente'}: {kind} {normalized}")

    if not apply_rules:
        console.print("Use --apply para aplicar regras locais de firewall agora.")
    console.print("Para tirar da rede inteira, bloqueie o MAC no roteador/AP quando ele aparecer acima.")
    notify_network_ban("ban por scan", normalized_targets, reason, apply_rules, failures)
    record_event(
        "network_ban_scan",
        ip=selected["ip"],
        mac=selected.get("mac") or None,
        reason=reason,
        applied=apply_rules,
        failures=failures,
    )
    return 0 if failures == 0 else 1


def repair_actions() -> list[tuple[str, list[str]]]:
    report = collect_health()
    actions: list[tuple[str, list[str]]] = []

    if not STATE_DIR.exists():
        actions.append(("Criar diretório de estado", ["mkdir", "-p", str(STATE_DIR)]))
    elif STATE_DIR.stat().st_mode & 0o077:
        actions.append(("Corrigir permissão do estado", ["chmod", "700", str(STATE_DIR)]))

    configured_env = next((path for path in ENV_PATHS if path.exists()), None)
    if configured_env:
        mode = configured_env.stat().st_mode & 0o777
        if mode & 0o077:
            actions.append(("Corrigir permissão do .env", ["chmod", "600", str(configured_env)]))

    for path in (Path(PROTECTED_DIR).expanduser(), Path(KNOWN_MACS_FILE).expanduser().parent):
        if not path.exists():
            actions.append((f"Criar {path}", ["mkdir", "-p", str(path)]))

    service_by_unit = {item["unit"]: item for item in report["services"]}
    for spec in SERVICES:
        item = service_by_unit.get(spec.unit)
        if not item or not spec.critical:
            continue
        if item["enabled"] not in {"enabled", "static"}:
            actions.append((f"Habilitar {spec.unit}", ["systemctl", "enable", spec.unit]))
        if item["state"] != "active":
            actions.append((f"Reiniciar {spec.unit}", ["systemctl", "restart", spec.unit]))

    return actions


def command_repair(apply: bool, quiet: bool = False) -> int:
    actions = repair_actions()
    if not actions:
        if not quiet:
            console.print("[green]Nenhum reparo necessário.[/]")
        return 0

    if not apply:
        table = Table(title="Reparos sugeridos", box=box.SIMPLE)
        table.add_column("Ação")
        table.add_column("Comando")
        for label, command in actions:
            table.add_row(label, " ".join(command))
        console.print(table)
        console.print("Use [bold]bunkerctl repair --apply[/] para executar.")
        return 1

    failures = 0
    for label, command in actions:
        result = run_system(command)
        ok = result.returncode == 0
        style = "green" if ok else "red"
        console.print(f"[{style}]{'OK' if ok else 'FALHA'}[/] {label}")
        if not ok:
            failures += 1
            detail = (result.stderr or result.stdout).strip()
            if detail:
                console.print(f"  {detail}")
    record_event("repair", applied=True, actions=len(actions), failures=failures)
    return 0 if failures == 0 else 1


def redact_env_line(line: str) -> str:
    if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
        return line
    key, _value = line.split("=", 1)
    normalized_key = key.strip().upper()
    if normalized_key not in SAFE_BACKUP_ENV_KEYS:
        return f"{key}=<redacted>"
    return line


def rotate_backups(backup_dir: Path, keep: int) -> list[Path]:
    if keep <= 0:
        return []
    backups = sorted(
        backup_dir.glob("kali-bunker-backup-*.tar.gz"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    removed = []
    for backup in backups[keep:]:
        backup.unlink()
        removed.append(backup)
    return removed


def command_backup(destination: str | None, include_secrets: bool, keep: int | None = None) -> int:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = Path(destination).expanduser() if destination else DEFAULT_BACKUP_DIR
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_path = backup_dir / f"kali-bunker-backup-{timestamp}.tar.gz"

    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory) / "kali-bunker"
        staging.mkdir()

        manifest = {
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "project_dir": str(PROJECT_DIR),
            "include_secrets": include_secrets,
            "files": [],
        }

        def copy_file(source: Path, relative: str, redact: bool = False) -> None:
            if not source.exists() or not source.is_file():
                return
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if redact:
                target.write_text(
                    "\n".join(redact_env_line(line) for line in source.read_text(encoding="utf-8").splitlines()) + "\n",
                    encoding="utf-8",
                )
            else:
                shutil.copy2(source, target)
            manifest["files"].append(relative)

        for index, env_path in enumerate(ENV_PATHS, start=1):
            if env_path.exists():
                suffix = "raw.env" if include_secrets else "redacted.env"
                copy_file(env_path, f"config/env-{index}.{suffix}", redact=not include_secrets)

        for unit in (PROJECT_DIR / "systemd").glob("*"):
            copy_file(unit, f"systemd/{unit.name}")

        for state_file in (AUDIT_LOG, STATE_DIR / "health-latest.json", STATE_DIR / "health-state.json"):
            copy_file(state_file, f"state/{state_file.name}")

        (staging / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        with tarfile.open(backup_path, "w:gz") as archive:
            archive.add(staging, arcname="kali-bunker")

    os.chmod(backup_path, 0o600)
    console.print(f"Backup criado em [bold]{backup_path}[/].")
    removed = rotate_backups(backup_dir, keep) if keep is not None else []
    if removed:
        console.print(f"Backups antigos removidos: {len(removed)}.")
    record_event("backup", output=str(backup_path), include_secrets=include_secrets, removed=len(removed))
    return 0


def install_check_items() -> list[dict[str, object]]:
    checks = doctor_checks()
    failed = [check for check in checks if not check["ok"]]
    env_found = any(path.exists() for path in ENV_PATHS)
    scanner = shutil.which("nmap") or shutil.which("arp-scan")
    firewall = shutil.which("iptables")
    service_failures = [
        check for check in checks if str(check["name"]).startswith("Serviço") and not check["ok"]
    ]
    return [
        {
            "item": "Configuracao local",
            "ok": env_found,
            "detail": "arquivo .env encontrado" if env_found else "crie um .env baseado em .env.example",
        },
        {
            "item": "Diagnostico geral",
            "ok": not failed,
            "detail": "todos os checks passaram" if not failed else f"{len(failed)} check(s) pendente(s)",
        },
        {
            "item": "Servicos systemd",
            "ok": not service_failures,
            "detail": "servicos OK" if not service_failures else "use bunkerctl repair --apply se houver falhas",
        },
        {
            "item": "Backup operacional",
            "ok": DEFAULT_BACKUP_DIR.exists(),
            "detail": f"diretorio {DEFAULT_BACKUP_DIR}",
        },
        {
            "item": "Auditoria",
            "ok": AUDIT_LOG.exists(),
            "detail": str(AUDIT_LOG),
        },
        {
            "item": "Scanner de rede",
            "ok": scanner is not None,
            "detail": scanner or "instale nmap ou arp-scan para usar bunkerctl ban scan",
        },
        {
            "item": "Firewall local",
            "ok": firewall is not None,
            "detail": firewall or "instale iptables para aplicar bunkerctl ban --apply",
        },
    ]


def command_install_check(as_json: bool) -> int:
    items = install_check_items()
    if as_json:
        console.print_json(json.dumps(items, ensure_ascii=False))
    else:
        table = Table(title="Checklist pos-instalacao", box=box.ROUNDED)
        table.add_column("Resultado", width=10)
        table.add_column("Item")
        table.add_column("Detalhe")
        for item in items:
            table.add_row(
                "[bright_green]OK[/]" if item["ok"] else "[bright_red]PENDENTE[/]",
                str(item["item"]),
                str(item["detail"]),
            )
        console.print(table)
        if any(not item["ok"] for item in items):
            console.print("Sugestao: rode [bold]bunkerctl doctor[/] e depois [bold]bunkerctl repair[/].")
    record_event("install_check", pending=sum(1 for item in items if not item["ok"]))
    return 0 if all(bool(item["ok"]) for item in items) else 1


def command_quick() -> int:
    table = Table(title="Kali Bunker - comandos rapidos", box=box.ROUNDED)
    table.add_column("Comando", style="bold bright_cyan")
    table.add_column("Uso")
    for command, description in QUICK_COMMANDS:
        table.add_row(command, description)
    console.print(table)
    return 0


def command_overview() -> int:
    report = collect_health()
    resources = report["resources"]
    active = sum(1 for item in report["services"] if item["state"] == "active")
    failed = len(report["critical_failed"])
    console.print(
        f"[bold bright_blue]Kali Bunker[/] "
        f"{'OK' if report['healthy'] else 'ATENCAO'} · "
        f"{active}/{len(report['services'])} servicos ativos · "
        f"{failed} critico(s) pendente(s)"
    )
    console.print(
        f"CPU {resources['cpu_percent']:.1f}% · "
        f"RAM {resources['memory_percent']:.1f}% · "
        f"Disco {resources['disk_percent']:.1f}% · "
        f"Temp {resources['temperature_c'] if resources['temperature_c'] is not None else 'N/D'}°C"
    )
    if report["critical_failed"]:
        console.print("Pendentes: " + ", ".join(report["critical_failed"]))
    return 0 if report["healthy"] else 1


def command_services(action: str) -> int:
    if action not in {"start", "stop", "restart"}:
        console.print(f"[red]Acao invalida:[/] {action}")
        return 2
    failures = 0
    for unit in CORE_SERVICE_UNITS:
        command = ["systemctl", action, unit]
        if os.geteuid() != 0 and shutil.which("sudo"):
            command = ["sudo", "-n", *command]
        result = run_system(command)
        ok = result.returncode == 0
        console.print(f"[{'green' if ok else 'red'}]{'OK' if ok else 'FALHA'}[/] {action} {unit}")
        if not ok:
            failures += 1
            detail = (result.stderr or result.stdout).strip()
            if detail:
                console.print(f"  {detail}")
            if "password" in detail.lower() or "sudo" in detail.lower():
                console.print("  Rode este comando em um terminal local com sudo: [bold]sudo kb " + {"start": "up", "stop": "down", "restart": "restart"}[action] + "[/]")
    record_event("services_control", action=action, units=len(CORE_SERVICE_UNITS), failures=failures)
    return 0 if failures == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="bunkerctl", description="Controle do Kali Bunker")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("quick", help="mostra os comandos mais usados")
    subparsers.add_parser("overview", help="mostra um resumo curto")
    subparsers.add_parser("up", help="liga os modulos principais")
    subparsers.add_parser("down", help="desliga os modulos principais")
    subparsers.add_parser("restart", help="reinicia os modulos principais")

    status = subparsers.add_parser("status")
    status.add_argument("--json", action="store_true")

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--fix", action="store_true", help="executa reparos seguros após o diagnóstico")

    subparsers.add_parser("alert-test")
    tools = subparsers.add_parser("tools")
    tools.add_argument("--category", choices=sorted({tool.category for tool in TOOLS}))
    tools.add_argument("--json", action="store_true")
    repair = subparsers.add_parser("repair")
    repair.add_argument("--apply", action="store_true", help="executa os reparos sugeridos")
    backup = subparsers.add_parser("backup")
    backup.add_argument("--destination", help="diretório de saída do backup")
    backup.add_argument("--include-secrets", action="store_true", help="inclui .env bruto no backup local")
    backup.add_argument("--keep", type=int, help="mantém apenas os últimos N backups no diretório")
    report = subparsers.add_parser("report")
    report.add_argument("--format", choices=("text", "json", "html"), default="text")
    report.add_argument("-o", "--output")
    report.add_argument("--audit-lines", type=int, default=10)
    install_check = subparsers.add_parser("install-check")
    install_check.add_argument("--json", action="store_true")
    network = subparsers.add_parser("network")
    network_subparsers = network.add_subparsers(dest="network_command", required=True)
    network_status = network_subparsers.add_parser("status")
    network_status.add_argument("--json", action="store_true")
    network_scan = network_subparsers.add_parser("scan")
    network_scan.add_argument("target", nargs="?", help="rede para escanear, exemplo: 192.168.3.0/24")
    network_scan.add_argument("--unknown-only", action="store_true", help="mostra apenas dispositivos nao conhecidos")
    network_scan.add_argument("--json", action="store_true")
    network_learn = network_subparsers.add_parser("learn")
    network_learn.add_argument("target", nargs="?", help="rede para aprender, exemplo: 192.168.3.0/24")
    network_learn.add_argument("--replace", action="store_true", help="substitui a lista de MACs conhecidos pelo scan atual")
    network_learn.add_argument("--json", action="store_true")
    ban = subparsers.add_parser("ban")
    ban_subparsers = ban.add_subparsers(dest="ban_command", required=True)
    ban_list = ban_subparsers.add_parser("list")
    ban_list.add_argument("--json", action="store_true")
    ban_add = ban_subparsers.add_parser("add")
    ban_add.add_argument("--ip")
    ban_add.add_argument("--mac")
    ban_add.add_argument("--reason", default="suspeito na rede")
    ban_add.add_argument("--apply", action="store_true", help="aplica regras locais de firewall")
    ban_remove = ban_subparsers.add_parser("remove")
    ban_remove.add_argument("--ip")
    ban_remove.add_argument("--mac")
    ban_remove.add_argument("--apply", action="store_true", help="remove regras locais de firewall")
    ban_scan = ban_subparsers.add_parser("scan")
    ban_scan.add_argument("target", nargs="?", help="rede para escanear, exemplo: 192.168.3.0/24")
    ban_scan.add_argument("--apply", action="store_true", help="aplica regras locais de firewall apos selecionar")
    ban_scan.add_argument("--unknown-only", action="store_true", help="mostra apenas dispositivos nao conhecidos")
    ban_scan.add_argument("--json", action="store_true")
    ban_scan.add_argument("--select", type=int, help="numero do dispositivo na lista do scan")
    ban_scan.add_argument("--ip", help="seleciona pelo IP encontrado no scan")
    ban_scan.add_argument("--mac", help="seleciona pelo MAC encontrado no scan")
    ban_scan.add_argument("--reason", default="suspeito encontrado no scan")
    ban_subparsers.add_parser("apply")
    logs = subparsers.add_parser("logs")
    logs.add_argument("unit")
    logs.add_argument("-n", "--lines", type=int, default=50)
    audit = subparsers.add_parser("audit")
    audit.add_argument("-n", "--lines", type=int, default=20)
    audit.add_argument("--export", choices=("json", "jsonl", "csv"), dest="export_format")
    audit.add_argument("-o", "--output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "quick":
        return command_quick()
    if args.command == "overview":
        return command_overview()
    if args.command == "up":
        return command_services("start")
    if args.command == "down":
        return command_services("stop")
    if args.command == "restart":
        return command_services("restart")
    if args.command == "status":
        return command_status(args.json)
    if args.command == "doctor":
        return command_doctor(args.json, args.fix)
    if args.command == "alert-test":
        return command_alert_test()
    if args.command == "tools":
        return command_tools(args.category, args.json)
    if args.command == "repair":
        return command_repair(args.apply)
    if args.command == "backup":
        return command_backup(args.destination, args.include_secrets, args.keep)
    if args.command == "report":
        return command_report(args.format, args.output, args.audit_lines)
    if args.command == "install-check":
        return command_install_check(args.json)
    if args.command == "network":
        if args.network_command == "status":
            return command_network_status(args.json)
        if args.network_command == "scan":
            return command_network_scan(args.target, args.unknown_only, args.json)
        if args.network_command == "learn":
            return command_network_learn(args.target, args.replace, args.json)
    if args.command == "ban":
        if args.ban_command == "list":
            return command_ban_list(args.json)
        if args.ban_command == "add":
            if bool(args.ip) == bool(args.mac):
                console.print("[red]Informe exatamente um alvo: --ip ou --mac.[/]")
                return 2
            kind = "ip" if args.ip else "mac"
            value = args.ip or args.mac
            return command_ban_add(kind, value, args.reason, args.apply)
        if args.ban_command == "remove":
            if bool(args.ip) == bool(args.mac):
                console.print("[red]Informe exatamente um alvo: --ip ou --mac.[/]")
                return 2
            kind = "ip" if args.ip else "mac"
            value = args.ip or args.mac
            return command_ban_remove(kind, value, args.apply)
        if args.ban_command == "scan":
            selectors = sum(1 for value in (args.select, args.ip, args.mac) if value is not None)
            if selectors > 1:
                console.print("[red]Use apenas um seletor: --select, --ip ou --mac.[/]")
                return 2
            return command_ban_scan(
                args.target,
                args.apply,
                args.unknown_only,
                args.json,
                args.select,
                args.ip,
                args.mac,
                args.reason,
            )
        if args.ban_command == "apply":
            return command_ban_apply()
    if args.command == "logs":
        return command_logs(args.unit, args.lines)
    if args.command == "audit":
        return command_audit(args.lines, args.export_format, args.output)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
