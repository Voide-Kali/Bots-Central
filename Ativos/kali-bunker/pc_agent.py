#!/usr/bin/env python3
"""Agente local do Kali Bunker para tarefas solicitadas pelo bot no servidor."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


VERSION = "1.1.0"
AGENT_ID = os.environ.get("PC_AGENT_ID", "kali-principal").strip() or "kali-principal"
SERVER = os.environ.get("PC_BRIDGE_SSH_HOST", "voide@100.87.201.41").strip()
REMOTE_SCRIPT = os.environ.get(
    "PC_BRIDGE_REMOTE_SCRIPT",
    "/home/voide/Projetos/gmail-telegram-bot/pc_bridge.py",
).strip()
POLL_SECONDS = max(1, int(os.environ.get("PC_AGENT_POLL_SECONDS", "1")))
METADATA_REFRESH_SECONDS = max(5, int(os.environ.get("PC_AGENT_METADATA_REFRESH_SECONDS", "30")))
LONG_POLL_SECONDS = max(0, min(int(os.environ.get("PC_AGENT_LONG_POLL_SECONDS", "30")), 60))
JOB_LEASE_SECONDS = max(120, int(os.environ.get("PC_JOB_LEASE_SECONDS", "900")))
COMMAND_TIMEOUT = max(10, int(os.environ.get("PC_AGENT_COMMAND_TIMEOUT", "300")))
MAX_OUTPUT_CHARS = max(1000, int(os.environ.get("PC_AGENT_MAX_OUTPUT_CHARS", "12000")))
MAX_FILE_MB = max(1, int(os.environ.get("PC_AGENT_MAX_FILE_MB", "45")))
WEBCAM_RESOLUTION = os.environ.get("WEBCAM_RESOLUTION", "1280x720").strip() or "1280x720"
WEBCAM_DEVICE = os.environ.get("WEBCAM_DEVICE", "").strip()
CONTROL_DIR = Path.home() / ".ssh" / "agent"
CONTROL_PATH = str(CONTROL_DIR / "kali-bunker-%C")
IDENTITY_FILE = Path(
    os.environ.get("PC_BRIDGE_SSH_IDENTITY", Path.home() / ".ssh" / "kali_bunker_agent")
).expanduser()
SHELL_FORBIDDEN_RE = re.compile(r"[\x00-\x1f\x7f;|&<>`]|\$\(")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]{0,63}$")

SERVICE_UNITS = {
    "BT": "bt-alarm.service",
    "AUTH": "monitor-auth.service",
    "SYS": "monitor-recursos.service",
    "WIFI": "monitor-wifi.service",
    "FILE": "monitor-arquivos.service",
    "USB": "usbguard.service",
    "BAN": "fail2ban.service",
}

logger = logging.getLogger("kali-bunker-pc-agent")


class BridgeError(RuntimeError):
    """Falha de comunicação com a fila no servidor."""


class BridgeClient:
    def __init__(self, server: str = SERVER, remote_script: str = REMOTE_SCRIPT) -> None:
        self.server = server
        self.remote_script = remote_script
        CONTROL_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            CONTROL_DIR.chmod(0o700)
        except OSError:
            pass

    def _ssh_base(self) -> list[str]:
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={CONTROL_PATH}",
            "-o",
            "ControlPersist=60",
        ]
        if IDENTITY_FILE.is_file():
            command.extend(["-i", str(IDENTITY_FILE), "-o", "IdentitiesOnly=yes"])
        command.append(self.server)
        return command

    def call(
        self,
        command: str,
        *arguments: str,
        payload: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        remote_argv = ["python3", self.remote_script, command, *arguments]
        remote_command = shlex.join(remote_argv)
        body = json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":"))
        try:
            result = subprocess.run(
                [*self._ssh_base(), remote_command],
                input=body,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BridgeError(f"servidor indisponível: {exc}") from exc
        output = result.stdout.strip().splitlines()
        if result.returncode != 0 or not output:
            detail = (result.stderr or result.stdout).strip()[-600:]
            raise BridgeError(detail or f"ponte retornou código {result.returncode}")
        try:
            response = json.loads(output[-1])
        except json.JSONDecodeError as exc:
            raise BridgeError("resposta inválida recebida do servidor") from exc
        if not isinstance(response, dict) or response.get("ok") is False:
            raise BridgeError(str(response.get("error", "operação recusada pela ponte")))
        return response

    def claim(self, metadata: dict[str, Any]) -> dict[str, Any] | None:
        arguments = [
            "--agent",
            AGENT_ID,
            "--lease",
            str(JOB_LEASE_SECONDS),
        ]
        if LONG_POLL_SECONDS > 0:
            arguments.extend(
                [
                    "--wait",
                    str(LONG_POLL_SECONDS),
                    "--interval",
                    str(POLL_SECONDS),
                ]
            )
        response = self.call(
            "claim",
            *arguments,
            payload={"metadata": metadata},
            timeout=max(30, LONG_POLL_SECONDS + 10),
        )
        job = response.get("job")
        return job if isinstance(job, dict) else None

    def heartbeat(self, metadata: dict[str, Any], last_error: str = "") -> None:
        self.call(
            "heartbeat",
            "--agent",
            AGENT_ID,
            payload={"metadata": metadata, "last_error": last_error},
        )

    def renew(self, job_id: str) -> dict[str, Any]:
        return self.call(
            "renew",
            "--agent",
            AGENT_ID,
            "--job",
            job_id,
            "--lease",
            str(JOB_LEASE_SECONDS),
        )

    def complete(
        self,
        job_id: str,
        *,
        ok: bool,
        result: str,
        artifact_name: str | None = None,
        canceled: bool = False,
    ) -> None:
        self.call(
            "complete",
            "--agent",
            AGENT_ID,
            "--job",
            job_id,
            payload={
                "ok": bool(ok),
                "result": str(result)[-MAX_OUTPUT_CHARS:],
                "artifact_name": artifact_name,
                "canceled": bool(canceled),
            },
        )

    def upload_artifact(self, job_id: str, local_path: Path) -> str:
        suffix = local_path.suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,8}", suffix):
            suffix = ".bin"
        target = self.call(
            "artifact-target",
            "--agent",
            AGENT_ID,
            "--job",
            job_id,
            "--suffix",
            suffix,
        )
        remote_path = str(target.get("path", ""))
        artifact_name = str(target.get("name", ""))
        if not remote_path or not artifact_name:
            raise BridgeError("servidor não preparou o recebimento do arquivo")
        command = [
            "scp",
            "-q",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={CONTROL_PATH}",
            "-o",
            "ControlPersist=60",
        ]
        if IDENTITY_FILE.is_file():
            command.extend(["-i", str(IDENTITY_FILE), "-o", "IdentitiesOnly=yes"])
        command.extend([str(local_path), f"{self.server}:{remote_path}"])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BridgeError(f"falha ao enviar arquivo: {exc}") from exc
        if result.returncode != 0:
            raise BridgeError((result.stderr or "falha no envio do arquivo").strip()[-600:])
        return artifact_name


def _command_output(argv: list[str], timeout: int = 8) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (result.stdout or result.stderr).strip()


def _service_states() -> dict[str, str]:
    units = list(SERVICE_UNITS.values())
    try:
        result = subprocess.run(
            ["systemctl", "is-active", *units],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        values = result.stdout.splitlines()
    except (OSError, subprocess.TimeoutExpired):
        values = []
    return {
        unit: (values[index].strip() if index < len(values) else "unknown")
        for index, unit in enumerate(units)
    }


def _local_ipv4() -> list[str]:
    output = _command_output(["ip", "-j", "-4", "address", "show"], timeout=5)
    try:
        interfaces = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return []
    values: list[str] = []
    for interface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(interface, dict) or interface.get("ifname") == "lo":
            continue
        for address in interface.get("addr_info", []):
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            local = str(address.get("local", ""))
            if local:
                values.append(local)
    return values[:12]


def _telemetry() -> dict[str, Any]:
    data: dict[str, Any] = {}
    try:
        import psutil  # type: ignore

        data = {
            "cpu_percent": round(float(psutil.cpu_percent(0.1)), 1),
            "ram_percent": round(float(psutil.virtual_memory().percent), 1),
            "disk_percent": round(float(psutil.disk_usage("/").percent), 1),
            "boot_time": int(psutil.boot_time()),
        }
        battery = psutil.sensors_battery()
        if battery:
            data["battery_percent"] = round(float(battery.percent), 1)
            data["power_plugged"] = bool(battery.power_plugged)
    except (ImportError, OSError, AttributeError):
        usage = shutil.disk_usage("/")
        data["disk_percent"] = round((usage.used / usage.total) * 100, 1)
    return data


def collect_metadata() -> dict[str, Any]:
    camera_devices = sorted(str(path) for path in Path("/dev").glob("video*"))
    return {
        "hostname": socket.gethostname(),
        "version": VERSION,
        "os": platform.platform(),
        "ips": _local_ipv4(),
        "capabilities": {
            "nmap": bool(shutil.which("nmap")),
            "webcam": bool(shutil.which("fswebcam")) and bool(camera_devices),
            "shell": True,
            "ssh": bool(shutil.which("ssh")),
            "services": bool(shutil.which("systemctl")),
        },
        "camera_devices": camera_devices,
        "services": _service_states(),
        "telemetry": _telemetry(),
    }


class MetadataCache:
    """Evita recomputar telemetria cara em cada consulta da fila."""

    def __init__(self, refresh_seconds: int = METADATA_REFRESH_SECONDS) -> None:
        self.refresh_seconds = max(1, int(refresh_seconds))
        self._value: dict[str, Any] | None = None
        self._updated_at = 0.0

    def get(self, *, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        if (
            force
            or self._value is None
            or now - self._updated_at >= self.refresh_seconds
        ):
            self._value = collect_metadata()
            self._updated_at = now
        return self._value

    def invalidate(self) -> None:
        self._value = None


def _default_network_target() -> str:
    route_output = _command_output(["ip", "-j", "route", "show", "default"], timeout=5)
    preferred_device = ""
    try:
        routes = json.loads(route_output)
        if isinstance(routes, list) and routes:
            preferred_device = str(routes[0].get("dev", ""))
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    address_output = _command_output(["ip", "-j", "-4", "address", "show"], timeout=5)
    try:
        interfaces = json.loads(address_output)
    except (json.JSONDecodeError, TypeError):
        interfaces = []
    candidates: list[tuple[int, ipaddress.IPv4Network]] = []
    for interface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(interface, dict):
            continue
        name = str(interface.get("ifname", ""))
        if name in {"lo", "tailscale0"} or name.startswith(("docker", "br-", "virbr", "veth")):
            continue
        priority = 0 if name == preferred_device else 1
        for address in interface.get("addr_info", []):
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            local = str(address.get("local", ""))
            prefix = int(address.get("prefixlen", 24))
            try:
                network = ipaddress.ip_interface(f"{local}/{prefix}").network
            except ValueError:
                continue
            if network.is_private and not network.is_loopback and network.num_addresses <= 65536:
                candidates.append((priority, network))
    if not candidates:
        return "192.168.1.0/24"
    candidates.sort(key=lambda item: (item[0], item[1].num_addresses))
    return str(candidates[0][1])


def _validate_network_target(value: str | None) -> str:
    selected = (value or "").strip() or _default_network_target()
    if selected.startswith("-") or len(selected) > 64:
        raise ValueError("alvo de rede inválido")
    try:
        target = ipaddress.ip_network(selected, strict=False)
    except ValueError:
        try:
            address = ipaddress.ip_address(selected)
        except ValueError as exc:
            raise ValueError("use um IPv4 ou CIDR válido") from exc
        target = ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)
    if target.version != 4 or not (target.is_private or target.is_loopback or target.is_link_local):
        raise ValueError("o scan remoto aceita somente uma rede IPv4 local")
    if target.num_addresses > 65536:
        raise ValueError("range grande demais; use no máximo /16")
    return selected


def _run_process(
    argv: list[str],
    *,
    job_id: str,
    bridge: BridgeClient,
    timeout: int,
) -> tuple[int, str, bool]:
    started = time.monotonic()
    canceled = False
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                cwd=str(Path.home()),
                shell=False,
            )
        except OSError as exc:
            return 127, str(exc), False
        next_renewal = time.monotonic() + 12
        while process.poll() is None:
            now = time.monotonic()
            if now - started >= timeout:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
            if now >= next_renewal:
                try:
                    renewal = bridge.renew(job_id)
                    if renewal.get("cancel_requested") or not renewal.get("valid", True):
                        canceled = True
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                        break
                except BridgeError:
                    logger.warning("Não foi possível renovar a tarefa %s; mantendo execução local.", job_id)
                next_renewal = now + 12
            time.sleep(0.5)
        returncode = process.wait()
        output_file.seek(0, os.SEEK_END)
        size = output_file.tell()
        output_file.seek(max(0, size - (MAX_OUTPUT_CHARS * 4)))
        output = output_file.read().decode("utf-8", errors="replace")[-MAX_OUTPUT_CHARS:].strip()
    if not canceled and time.monotonic() - started >= timeout and returncode != 0:
        output = f"Tempo limite de {timeout}s excedido.\n{output}".strip()
        returncode = 124
    return returncode, output or "(sem saída)", canceled


def _format_scan(raw_output: str, target: str) -> str:
    hosts: list[str] = []
    current = ""
    for line in raw_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for "):
            current = stripped.removeprefix("Nmap scan report for ")
            hosts.append(f"• {current}")
        elif stripped.startswith("MAC Address:") and hosts:
            hosts[-1] += f" — {stripped}"
    if not hosts:
        return f"Scan concluído em {target}. Nenhum host respondeu.\n\n{raw_output[-2500:]}"
    return f"Scan concluído em {target}: {len(hosts)} host(s) ativo(s).\n\n" + "\n".join(hosts[:80])


def _shell_argv(command: str) -> list[str]:
    normalized = command.strip()
    if not normalized or len(normalized) > 8192:
        raise ValueError("comando vazio ou grande demais")
    if SHELL_FORBIDDEN_RE.search(normalized):
        raise ValueError("o agente aceita um comando por tarefa, sem operadores de shell")
    try:
        argv = shlex.split(normalized, posix=True)
    except ValueError as exc:
        raise ValueError(f"comando inválido: {exc}") from exc
    if not argv or argv[0].startswith("-"):
        raise ValueError("executável inválido")
    return argv


def _camera_devices() -> list[str]:
    if WEBCAM_DEVICE and Path(WEBCAM_DEVICE).exists():
        return [WEBCAM_DEVICE]
    return [str(device) for device in sorted(Path("/dev").glob("video*"))]


def _execute_webcam(job_id: str, bridge: BridgeClient) -> tuple[bool, str, Path | None, bool]:
    executable = shutil.which("fswebcam")
    devices = _camera_devices()
    if not executable:
        return False, "fswebcam não está instalado no PC.", None, False
    if not devices:
        return False, "Nenhuma webcam foi detectada em /dev/video*. Conecte ou habilite a câmera.", None, False
    output_dir = Path(tempfile.mkdtemp(prefix="kali-bunker-camera-"))
    photo_path = output_dir / "webcam.jpg"
    errors: list[str] = []
    for device in devices:
        photo_path.unlink(missing_ok=True)
        argv = [
            executable,
            "--quiet",
            "--no-banner",
            "--frames",
            "1",
            "--resolution",
            WEBCAM_RESOLUTION,
            "--device",
            device,
            str(photo_path),
        ]
        status, output, canceled = _run_process(argv, job_id=job_id, bridge=bridge, timeout=15)
        if canceled:
            shutil.rmtree(output_dir, ignore_errors=True)
            return False, "Captura cancelada.", None, True
        if status == 0 and photo_path.is_file() and photo_path.stat().st_size > 0:
            return True, f"Foto capturada pela webcam {device}.", photo_path, False
        errors.append(f"{device}: {output[-300:]}")
    shutil.rmtree(output_dir, ignore_errors=True)
    return False, "Nenhuma câmera conseguiu capturar uma imagem.\n" + "\n".join(errors), None, False


def _local_session_ids() -> list[str]:
    output = _command_output(["loginctl", "list-sessions", "--no-legend", "--no-pager"], timeout=8)
    sessions: list[str] = []
    user = os.environ.get("USER", "")
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3 and (fields[2] == user or fields[1] == str(os.getuid())):
            sessions.append(fields[0])
    return sessions


def _execute_session_action(
    action: str,
    job_id: str,
    bridge: BridgeClient,
) -> tuple[bool, str, bool]:
    verb = "lock-session" if action == "lock" else "unlock-session"
    sessions = _local_session_ids()
    if not sessions:
        return False, "Nenhuma sessão gráfica local do usuário foi encontrada.", False
    errors: list[str] = []
    for session_id in sessions:
        status, output, canceled = _run_process(
            ["loginctl", verb, session_id],
            job_id=job_id,
            bridge=bridge,
            timeout=12,
        )
        if canceled:
            return False, output, True
        if status == 0:
            label = "bloqueada" if action == "lock" else "desbloqueada"
            return True, f"Sessão {session_id} {label}.", False
        errors.append(f"sessão {session_id}: {output[-300:]}")
    return False, "\n".join(errors), False


def _execute_service(
    job_id: str,
    bridge: BridgeClient,
    payload: dict[str, Any],
) -> tuple[bool, str, bool]:
    action = str(payload.get("service_action", "")).strip().lower()
    code = str(payload.get("service_code", "")).strip().upper()
    if action not in {"start", "stop", "restart"} or code not in SERVICE_UNITS:
        return False, "Ação ou código de serviço inválido.", False
    service = shutil.which("service") or "/usr/sbin/service"
    unit_name = SERVICE_UNITS[code].removesuffix(".service")
    argv = ["sudo", "-n", service, unit_name, action]
    status, output, canceled = _run_process(argv, job_id=job_id, bridge=bridge, timeout=60)
    systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
    state = _command_output([systemctl, "is-active", SERVICE_UNITS[code]], timeout=5) or "desconhecido"
    detail = f"{code}: {action} concluído; estado atual: {state}."
    if status != 0:
        detail = f"Não foi possível executar {action} em {code}.\n{output}"
    return status == 0, detail, canceled


def _execute_service_logs(
    job_id: str,
    bridge: BridgeClient,
    payload: dict[str, Any],
) -> tuple[bool, str, bool]:
    code = str(payload.get("service_code", "")).strip().upper()
    if code not in SERVICE_UNITS:
        return False, "Código de serviço inválido.", False
    try:
        lines = max(1, min(int(payload.get("lines", 80)), 300))
    except (TypeError, ValueError):
        lines = 80
    status, output, canceled = _run_process(
        ["journalctl", "-u", SERVICE_UNITS[code], "-n", str(lines), "--no-pager"],
        job_id=job_id,
        bridge=bridge,
        timeout=30,
    )
    return status == 0, f"{code} · {SERVICE_UNITS[code]}\n\n{output}", canceled


def _execute_power_action(
    action: str,
    job_id: str,
    bridge: BridgeClient,
) -> tuple[bool, str, bool]:
    if action in {"shutdown", "reboot"}:
        shutdown = shutil.which("shutdown") or "/usr/sbin/shutdown"
        flag = "-h" if action == "shutdown" else "-r"
        status, output, canceled = _run_process(
            ["sudo", "-n", shutdown, flag, "+1"],
            job_id=job_id,
            bridge=bridge,
            timeout=20,
        )
        label = "desligamento" if action == "shutdown" else "reinicialização"
        detail = f"{label.capitalize()} do PC agendado para daqui a 1 minuto."
        return status == 0, detail if status == 0 else output, canceled
    systemd_run = shutil.which("systemd-run") or "/usr/bin/systemd-run"
    systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"
    status, output, canceled = _run_process(
        [
            systemd_run,
            "--user",
            "--unit",
            f"kali-bunker-suspend-{job_id}",
            "--on-active=15s",
            systemctl,
            "suspend",
        ],
        job_id=job_id,
        bridge=bridge,
        timeout=20,
    )
    detail = "Suspensão do PC agendada para daqui a 15 segundos."
    return status == 0, detail if status == 0 else output, canceled


def _execute_cleanup(job_id: str, bridge: BridgeClient) -> tuple[bool, str, bool]:
    candidates = (
        Path.home() / "Kali-Bunker-main" / "limpeza-semanal.sh",
        Path("/opt/kali-bunker/limpeza-semanal.sh"),
    )
    script = next((path for path in candidates if path.is_file()), None)
    if not script:
        return False, "Script de limpeza do Kali Bunker não foi encontrado.", False
    status, output, canceled = _run_process(
        ["sudo", "-n", str(script)],
        job_id=job_id,
        bridge=bridge,
        timeout=900,
    )
    return status == 0, "Limpeza do PC concluída.\n\n" + output, canceled


def _execute_emergency(
    job_id: str,
    bridge: BridgeClient,
    *,
    include_cleanup: bool,
) -> tuple[bool, str, bool]:
    details: list[str] = []
    lock_status, lock_output, canceled = _run_process(
        ["loginctl", "lock-sessions"],
        job_id=job_id,
        bridge=bridge,
        timeout=20,
    )
    details.append(f"Bloqueio: {'ok' if lock_status == 0 else lock_output}")
    if canceled:
        return False, "\n".join(details), True
    ok_all = lock_status == 0
    service = shutil.which("service") or "/usr/sbin/service"
    for code in ("BT", "AUTH", "SYS", "WIFI", "FILE"):
        status, output, canceled = _run_process(
            [
                "sudo",
                "-n",
                service,
                SERVICE_UNITS[code].removesuffix(".service"),
                "restart",
            ],
            job_id=job_id,
            bridge=bridge,
            timeout=60,
        )
        ok_all = ok_all and status == 0
        details.append(f"{code}: {'ok' if status == 0 else output[-300:]}")
        if canceled:
            return False, "\n".join(details), True
    if include_cleanup:
        cleanup_ok, cleanup_output, canceled = _execute_cleanup(job_id, bridge)
        ok_all = ok_all and cleanup_ok
        details.append(f"Limpeza: {'ok' if cleanup_ok else cleanup_output[-500:]}")
        if canceled:
            return False, "\n".join(details), True
    return ok_all, "Modo emergência concluído.\n\n" + "\n".join(details), False


def _execute_send_path(payload: dict[str, Any]) -> tuple[bool, str, Path | None]:
    raw = str(payload.get("path", "")).strip()
    if not raw:
        return False, "Caminho não informado.", None
    candidate = Path(raw).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        return False, f"Arquivo não encontrado: {exc}", None
    allowed_roots = [
        (Path.home() / name).resolve()
        for name in ("Documentos", "Documents", "Downloads", "Imagens", "Pictures", "Área de Trabalho", "Desktop")
        if (Path.home() / name).is_dir()
    ]
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        return False, "O arquivo precisa estar em Documentos, Downloads, Imagens ou Área de Trabalho.", None
    if not resolved.is_file() or resolved.is_symlink():
        return False, "O envio remoto aceita um arquivo comum por vez.", None
    if resolved.stat().st_size > MAX_FILE_MB * 1024 * 1024:
        return False, f"Arquivo maior que o limite de {MAX_FILE_MB} MB.", None
    return True, f"Arquivo recebido do PC: {resolved.name}", resolved


def execute_job(
    job: dict[str, Any],
    bridge: BridgeClient,
) -> tuple[bool, str, Path | None, bool]:
    job_id = str(job.get("job_id", ""))
    action = str(job.get("action", ""))
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    if action == "status":
        metadata = collect_metadata()
        telemetry = metadata.get("telemetry", {})
        services = metadata.get("services", {})
        active = sum(value == "active" for value in services.values())
        detail = (
            f"PC {metadata['hostname']} online.\n"
            f"IPs: {', '.join(metadata.get('ips', [])) or 'N/D'}\n"
            f"CPU: {telemetry.get('cpu_percent', 'N/D')}% · "
            f"RAM: {telemetry.get('ram_percent', 'N/D')}% · "
            f"Disco: {telemetry.get('disk_percent', 'N/D')}%\n"
            f"Serviços ativos: {active}/{len(services)}"
        )
        return True, detail, None, False
    if action == "network_scan":
        try:
            target = _validate_network_target(str(payload.get("target", "")))
        except ValueError as exc:
            return False, str(exc), None, False
        nmap = shutil.which("nmap")
        if not nmap:
            return False, "nmap não está instalado no PC.", None, False
        status, output, canceled = _run_process(
            [nmap, "-sn", target],
            job_id=job_id,
            bridge=bridge,
            timeout=max(30, int(payload.get("timeout", 120))),
        )
        return status == 0, _format_scan(output, target) if status == 0 else output, None, canceled
    if action == "webcam":
        return _execute_webcam(job_id, bridge)
    if action == "shell":
        try:
            argv = _shell_argv(str(payload.get("command", "")))
        except ValueError as exc:
            return False, str(exc), None, False
        status, output, canceled = _run_process(
            argv,
            job_id=job_id,
            bridge=bridge,
            timeout=max(10, min(int(payload.get("timeout", COMMAND_TIMEOUT)), 1800)),
        )
        return status == 0, f"Código de saída: {status}\n\n{output}", None, canceled
    if action == "service":
        ok, detail, canceled = _execute_service(job_id, bridge, payload)
        return ok, detail, None, canceled
    if action == "service_logs":
        ok, detail, canceled = _execute_service_logs(job_id, bridge, payload)
        return ok, detail, None, canceled
    if action == "lock":
        ok, detail, canceled = _execute_session_action("lock", job_id, bridge)
        return ok, detail, None, canceled
    if action == "unlock":
        ok, detail, canceled = _execute_session_action("unlock", job_id, bridge)
        return ok, detail, None, canceled
    if action in {"shutdown", "reboot", "suspend"}:
        ok, detail, canceled = _execute_power_action(action, job_id, bridge)
        return ok, detail, None, canceled
    if action == "cleanup":
        ok, detail, canceled = _execute_cleanup(job_id, bridge)
        return ok, detail, None, canceled
    if action == "emergency":
        ok, detail, canceled = _execute_emergency(
            job_id,
            bridge,
            include_cleanup=bool(payload.get("include_cleanup")),
        )
        return ok, detail, None, canceled
    if action == "send_path":
        ok, detail, path = _execute_send_path(payload)
        return ok, detail, path, False
    if action == "install_package":
        package = str(payload.get("package", "")).strip()
        if not PACKAGE_RE.fullmatch(package):
            return False, "Nome de pacote inválido.", None, False
        dry_status, dry_output, canceled = _run_process(
            ["apt-get", "install", "--dry-run", "--no-remove", "--", package],
            job_id=job_id,
            bridge=bridge,
            timeout=120,
        )
        if canceled or dry_status != 0:
            return False, dry_output, None, canceled
        status, output, canceled = _run_process(
            ["sudo", "-n", "apt-get", "install", "--yes", "--no-remove", "--", package],
            job_id=job_id,
            bridge=bridge,
            timeout=1800,
        )
        detail = f"Pacote {package} instalado.\n\n{output}" if status == 0 else output
        return status == 0, detail, None, canceled
    return False, f"Ação desconhecida: {action}", None, False


def _finish_job(
    bridge: BridgeClient,
    job: dict[str, Any],
    ok: bool,
    result: str,
    artifact: Path | None,
    canceled: bool,
) -> None:
    job_id = str(job["job_id"])
    artifact_name: str | None = None
    try:
        if ok and artifact:
            artifact_name = bridge.upload_artifact(job_id, artifact)
        for attempt in range(12):
            try:
                bridge.complete(
                    job_id,
                    ok=ok,
                    result=result,
                    artifact_name=artifact_name,
                    canceled=canceled,
                )
                return
            except BridgeError:
                if attempt == 11:
                    raise
                time.sleep(5)
    finally:
        if artifact and artifact.parent.name.startswith("kali-bunker-camera-"):
            shutil.rmtree(artifact.parent, ignore_errors=True)


def run_forever() -> None:
    bridge = BridgeClient()
    metadata_cache = MetadataCache()
    logger.info(
        "Agente %s iniciado; servidor %s; polling=%ss; long-poll=%ss; telemetria=%ss.",
        AGENT_ID,
        SERVER,
        POLL_SECONDS,
        LONG_POLL_SECONDS,
        METADATA_REFRESH_SECONDS,
    )
    last_error_log = 0.0
    while True:
        try:
            job = bridge.claim(metadata_cache.get())
            if not job:
                # A chamada claim já aguardou no servidor quando long-poll está ativo.
                # Só dorme no modo legado para não criar um busy loop.
                if LONG_POLL_SECONDS <= 0:
                    time.sleep(POLL_SECONDS)
                continue
            logger.info("Executando tarefa %s (%s).", job.get("job_id"), job.get("action"))
            ok, result, artifact, canceled = execute_job(job, bridge)
            _finish_job(bridge, job, ok, result, artifact, canceled)
            # A próxima publicação deve refletir imediatamente mudanças causadas
            # pela ação recém-executada (serviços, energia, rede etc.).
            metadata_cache.invalidate()
            logger.info(
                "Tarefa %s finalizada: %s.",
                job.get("job_id"),
                "cancelada" if canceled else "ok" if ok else "falha",
            )
        except KeyboardInterrupt:
            logger.info("Agente encerrado.")
            return
        except Exception as exc:
            now = time.monotonic()
            if now - last_error_log >= 30:
                logger.warning("Ponte indisponível; tentando novamente: %s", exc)
                last_error_log = now
            time.sleep(max(POLL_SECONDS, 5))


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("PC_AGENT_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run_forever()


if __name__ == "__main__":
    main()
