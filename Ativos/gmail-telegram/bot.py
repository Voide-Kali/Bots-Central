"""Interface Telegram e orquestração do monitor Gmail."""

from __future__ import annotations

import asyncio
import getpass
import html
import ipaddress
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psutil
from telegram import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.error import BadRequest, Conflict
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

import config
import db
import pc_bridge
from gmail_client import get_gmail_service, get_unread_count, get_unread_emails
from summarizer import summarize_email

KALI_BUNKER_DIR = getattr(config, "KALI_BUNKER_DIR", None)

try:
    if not KALI_BUNKER_DIR:
        raise ImportError("KALI_BUNKER_DIR não configurado")
    kali_bunker_path = str(Path(KALI_BUNKER_DIR).expanduser().resolve())
    if not Path(kali_bunker_path).is_dir():
        raise ImportError(f"Kali Bunker não encontrado em {kali_bunker_path}")
    if kali_bunker_path not in sys.path:
        sys.path.insert(0, kali_bunker_path)
    from remote_control import (
        ai_assistant,
        cancel_pending,
        create_pending,
        execute_shell,
        execute_typed_action,
        pop_pending,
    )
except Exception:  # pragma: no cover - recurso opcional no ambiente local/servidor
    ai_assistant = None
    cancel_pending = create_pending = execute_shell = execute_typed_action = pop_pending = None


logger = logging.getLogger(__name__)
gmail_services: dict[str, dict[str, Any]] = {}
check_lock = asyncio.Lock()
power_lock = asyncio.Lock()
cleanup_lock = asyncio.Lock()
system_action_lock = asyncio.Lock()
PROJECT_DIR = getattr(config, "PROJECT_DIR", None)
LOG_LINE_LIMIT = 80
NETWORK_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]{3,64}$")
PC_AGENT_ID = str(getattr(config, "PC_AGENT_ID", pc_bridge.DEFAULT_AGENT_ID))
PC_SERVICE_CODES = {"BT", "AUTH", "SYS", "WIFI", "FILE", "USB", "BAN"}
PC_ACTION_LABELS = {
    "status": "Status do PC",
    "shell": "Comando no PC",
    "network_scan": "Scan de rede",
    "webcam": "Webcam",
    "service": "Serviço do PC",
    "service_logs": "Logs do PC",
    "lock": "Bloquear tela",
    "unlock": "Desbloquear tela",
    "shutdown": "Desligar PC",
    "reboot": "Reiniciar PC",
    "suspend": "Suspender PC",
    "cleanup": "Limpeza do PC",
    "emergency": "Modo emergência",
    "send_path": "Arquivo do PC",
    "install_package": "Instalar pacote",
}


@dataclass
class MonitorState:
    started_at: float = field(default_factory=time.time)
    last_check_at: datetime | None = None
    last_check_duration: float = 0
    last_new_emails: int = 0
    total_notifications: int = 0
    checks_completed: int = 0
    account_errors: dict[str, str] = field(default_factory=dict)
    last_battery_alert_at: float = 0
    last_power_plugged: bool | None = None
    low_battery_alerted: bool = False
    last_daily_report_date: str | None = None
    silence_until: float = 0
    maintenance_until: float = 0
    suppressed_notifications: int = 0
    high_cpu_since: float | None = None
    high_temp_since: float | None = None
    last_resource_alert_at: float = 0
    known_failed_services: set[str] = field(default_factory=set)


state = MonitorState()

SECURITY_SERVICES = (
    ("bt-alarm.service", "Alarme Bluetooth", "BT"),
    ("monitor-auth.service", "Autenticação", "AUTH"),
    ("monitor-recursos.service", "CPU e memória", "SYS"),
    ("monitor-wifi.service", "Rede Wi-Fi", "WIFI"),
    ("monitor-arquivos.service", "Arquivos", "FILE"),
    ("usbguard.service", "USBGuard", "USB"),
    ("fail2ban.service", "Fail2Ban", "BAN"),
    ("gmail-telegram-bot.service", "Monitor Gmail", "MAIL"),
    ("estudos-bot.service", "Assistente de estudos", "STUDY"),
)

SERVICE_BY_CODE = {code: (unit, name, code) for unit, name, code in SECURITY_SERVICES}
SERVICE_BY_UNIT = {unit: (unit, name, code) for unit, name, code in SECURITY_SERVICES}
CORE_SECURITY_CODES = ("BT", "AUTH", "SYS", "WIFI", "FILE")


def get_chat_id() -> int:
    try:
        return int(str(config.TELEGRAM_CHAT_ID).strip())
    except (TypeError, ValueError) as exc:
        raise RuntimeError("TELEGRAM_CHAT_ID deve ser um número inteiro.") from exc


def get_allowed_user_ids() -> set[int]:
    raw = str(getattr(config, "TELEGRAM_ALLOWED_USER_IDS", "") or "").strip()
    if not raw:
        # Em chat privado, chat_id == user_id. Em grupos, esse fallback bloqueia
        # membros até TELEGRAM_ALLOWED_USER_IDS ser configurado explicitamente.
        return {get_chat_id()}

    allowed_ids: set[int] = set()
    for item in raw.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            allowed_ids.add(int(value))
        except ValueError as exc:
            raise RuntimeError(
                "TELEGRAM_ALLOWED_USER_IDS deve conter apenas IDs numéricos separados por vírgula."
            ) from exc

    if not allowed_ids:
        raise RuntimeError("TELEGRAM_ALLOWED_USER_IDS não contém nenhum ID válido.")
    return allowed_ids


def allowed(update: Update) -> bool:
    chat = update.effective_chat
    user = update.effective_user
    expected_chat_id = get_chat_id()
    permitted = bool(
        chat
        and chat.id == expected_chat_id
        and user
        and user.id in get_allowed_user_ids()
    )
    if not permitted:
        logger.warning(
            "Acesso Telegram recusado: chat=%s user=%s",
            getattr(chat, "id", None),
            getattr(user, "id", None),
        )
    return permitted


def validate_config() -> None:
    missing = []
    if not config.TELEGRAM_TOKEN:
        missing.append("TELEGRAM_TOKEN")
    if not config.TELEGRAM_CHAT_ID:
        missing.append("TELEGRAM_CHAT_ID")
    if not config.GMAIL_ACCOUNTS:
        missing.append("GMAIL_ACCOUNTS")
    if missing:
        raise RuntimeError(f"Configuração incompleta: {', '.join(missing)}")
    get_chat_id()
    get_allowed_user_ids()
    if config.CHECK_INTERVAL_SECONDS < 10:
        raise RuntimeError("CHECK_INTERVAL_SECONDS deve ser >= 10.")
    if config.MAX_EMAILS_PER_CHECK < 1:
        raise RuntimeError("MAX_EMAILS_PER_CHECK deve ser >= 1.")


def project_path(path: str) -> str:
    value = Path(path).expanduser()
    if value.is_absolute():
        return str(value)
    base = Path(PROJECT_DIR) if PROJECT_DIR else Path(__file__).resolve().parent
    return str(base / value)


def account_label(account: dict) -> str:
    return str(account.get("label") or account.get("email") or "Conta Gmail")


def is_important_email(email: dict) -> bool:
    sender = (email.get("sender") or "").lower()
    subject = (email.get("subject") or "").lower()
    ignored = (
        getattr(config, "IGNORE_SENDERS", [])
        + getattr(config, "IGNORE_SENDER_DOMAINS", [])
    )
    if any(item and (item in sender or item in subject) for item in ignored):
        return False
    return not any(
        word and word in subject
        for word in getattr(config, "IGNORE_SUBJECT_KEYWORDS", [])
    )


def init_gmail_services() -> None:
    gmail_services.clear()
    state.account_errors.clear()
    for account in config.GMAIL_ACCOUNTS:
        address = account.get("email")
        if not address:
            logger.error("Conta Gmail sem campo email: %s", account)
            continue
        try:
            service = get_gmail_service(
                project_path(account["credentials_file"]),
                project_path(account["token_file"]),
                interactive=False,
            )
            gmail_services[address] = {
                "service": service,
                "label": account_label(account),
                "email": address,
            }
            logger.info("Conta autenticada: %s", address)
        except Exception as exc:
            state.account_errors[address] = str(exc)
            logger.error("Falha ao autenticar %s: %s", address, exc)


def main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🛡️ Segurança", callback_data="security"),
                InlineKeyboardButton("💻 Sistema", callback_data="system"),
            ],
            [
                InlineKeyboardButton("📨 Gmail", callback_data="gmail"),
                InlineKeyboardButton("🔄 Atualizar", callback_data="dashboard"),
            ],
            [
                InlineKeyboardButton("🤖 Voz IA", callback_data="ai_menu"),
                InlineKeyboardButton("🖥️ Meu PC", callback_data="pc_panel"),
            ],
            [
                InlineKeyboardButton("📋 Tarefas", callback_data="pc_jobs"),
            ],
            [
                InlineKeyboardButton("⚙️ Operações", callback_data="ops"),
                InlineKeyboardButton("🧩 Serviços", callback_data="svc_menu"),
            ],
            [
                InlineKeyboardButton("📜 Logs", callback_data="logs_menu"),
                InlineKeyboardButton("🌐 Rede", callback_data="network_menu"),
            ],
            [
                InlineKeyboardButton("⏻ Desligar", callback_data="shutdown_confirm"),
                InlineKeyboardButton("↻ Reiniciar", callback_data="reboot_confirm"),
            ],
            [
                InlineKeyboardButton("⏾ Suspender", callback_data="suspend_confirm"),
            ],
            [
                InlineKeyboardButton("🧹 Limpeza agora", callback_data="cleanup_confirm"),
            ],
            [
                InlineKeyboardButton("ℹ️ Central e ajuda", callback_data="help"),
            ],
        ]
    )


def back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard")]]
    )


def operations_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔒 Bloquear tela", callback_data="lock_confirm"),
                InlineKeyboardButton("🔓 Desbloquear", callback_data="unlock_confirm"),
            ],
            [
                InlineKeyboardButton("🚨 Emergência", callback_data="emergency_confirm"),
            ],
            [
                InlineKeyboardButton("📋 Relatório", callback_data="report"),
                InlineKeyboardButton("📷 Webcam", callback_data="webcam_confirm"),
            ],
            [
                InlineKeyboardButton("🔕 Silenciar", callback_data="silence_menu"),
                InlineKeyboardButton("🛠️ Manutenção", callback_data="maintenance_menu"),
            ],
            [
                InlineKeyboardButton("✅ Integridade", callback_data="integrity"),
                InlineKeyboardButton("🧾 Histórico", callback_data="history"),
            ],
            [
                InlineKeyboardButton("⬆️ Atualização", callback_data="updates_menu"),
                InlineKeyboardButton("🔐 Permissões", callback_data="permissions"),
            ],
            [
                InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard"),
            ],
        ]
    )


def service_menu_keyboard() -> InlineKeyboardMarkup:
    rows = []
    for _, name, code in SECURITY_SERVICES:
        rows.append([InlineKeyboardButton(f"{code} · {name}", callback_data=f"svc_{code}")])
    rows.append([InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard")])
    return InlineKeyboardMarkup(rows)


def service_action_keyboard(code: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔄 Reiniciar", callback_data=f"svc_restart_confirm_{code}"),
                InlineKeyboardButton("▶️ Iniciar", callback_data=f"svc_start_confirm_{code}"),
            ],
            [
                InlineKeyboardButton("⏹️ Parar", callback_data=f"svc_stop_confirm_{code}"),
                InlineKeyboardButton("📜 Logs", callback_data=f"logs_{code}"),
            ],
            [
                InlineKeyboardButton("‹ Serviços", callback_data="svc_menu"),
                InlineKeyboardButton("Painel", callback_data="dashboard"),
            ],
        ]
    )


def service_confirm_keyboard(action: str, code: str) -> InlineKeyboardMarkup:
    labels = {
        "restart": "Sim, reiniciar",
        "start": "Sim, iniciar",
        "stop": "Sim, parar",
    }
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(labels[action], callback_data=f"svc_{action}_now_{code}"),
                InlineKeyboardButton("Cancelar", callback_data=f"svc_{code}"),
            ]
        ]
    )


def logs_menu_keyboard() -> InlineKeyboardMarkup:
    rows = []
    for _, name, code in SECURITY_SERVICES:
        rows.append([InlineKeyboardButton(f"{code} · {name}", callback_data=f"logs_{code}")])
    rows.append([InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard")])
    return InlineKeyboardMarkup(rows)


def network_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🌐 Escanear rede", callback_data="scan_confirm"),
                InlineKeyboardButton("💻 Status rápido", callback_data="quick_status"),
            ],
            [
                InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard"),
            ],
        ]
    )


def pc_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔄 Atualizar", callback_data="pc_panel"),
                InlineKeyboardButton("📋 Tarefas", callback_data="pc_jobs"),
            ],
            [
                InlineKeyboardButton("🌐 Scan no PC", callback_data="scan_confirm"),
                InlineKeyboardButton("📷 Foto do PC", callback_data="webcam_confirm"),
            ],
            [
                InlineKeyboardButton("🩺 Testar conexão", callback_data="pc_status_request"),
            ],
            [InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard")],
        ]
    )


def pc_jobs_keyboard(jobs: list[dict[str, Any]]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for job in jobs[:8]:
        job_id = str(job.get("job_id", ""))
        status = str(job.get("status", ""))
        icon = {
            "queued": "⏳",
            "running": "⚙️",
            "completed": "✅",
            "failed": "❌",
            "canceled": "🚫",
        }.get(status, "•")
        rows.append(
            [InlineKeyboardButton(f"{icon} {job_id}", callback_data=f"pc_job_{job_id}")]
        )
    rows.append(
        [
            InlineKeyboardButton("🔄 Atualizar", callback_data="pc_jobs"),
            InlineKeyboardButton("‹ Meu PC", callback_data="pc_panel"),
        ]
    )
    return InlineKeyboardMarkup(rows)


def pc_job_keyboard(job: dict[str, Any]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    job_id = str(job.get("job_id", ""))
    if str(job.get("status", "")) in {"queued", "running"}:
        rows.append(
            [InlineKeyboardButton("🛑 Cancelar tarefa", callback_data=f"pc_cancel_{job_id}")]
        )
    rows.append(
        [
            InlineKeyboardButton("‹ Tarefas", callback_data="pc_jobs"),
            InlineKeyboardButton("Painel", callback_data="dashboard"),
        ]
    )
    return InlineKeyboardMarkup(rows)


def gmail_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔄 Verificar agora", callback_data="check"),
                InlineKeyboardButton("📬 Contas", callback_data="accounts"),
            ],
            [
                InlineKeyboardButton("📈 Estatísticas", callback_data="stats"),
                InlineKeyboardButton("‹ Central Bunker", callback_data="dashboard"),
            ],
        ]
    )


def shutdown_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("⏻ Sim, desligar", callback_data="shutdown_now"),
                InlineKeyboardButton("Cancelar", callback_data="dashboard"),
            ]
        ]
    )


def reboot_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("↻ Sim, reiniciar", callback_data="reboot_now"),
                InlineKeyboardButton("Cancelar", callback_data="dashboard"),
            ]
        ]
    )


def suspend_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("⏾ Sim, suspender", callback_data="suspend_now"),
                InlineKeyboardButton("Cancelar", callback_data="dashboard"),
            ]
        ]
    )


def cleanup_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🧹 Sim, limpar", callback_data="cleanup_now"),
                InlineKeyboardButton("Cancelar", callback_data="dashboard"),
            ]
        ]
    )


def lock_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔒 Sim, bloquear", callback_data="lock_now"),
          InlineKeyboardButton("Cancelar", callback_data="ops")]]
    )


def unlock_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🔓 Sim, desbloquear", callback_data="unlock_now"),
          InlineKeyboardButton("Cancelar", callback_data="ops")]]
    )


def emergency_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🚨 Executar", callback_data="emergency_now"),
            ],
            [
                InlineKeyboardButton("🚨 Executar + limpeza", callback_data="emergency_cleanup_now"),
            ],
            [
                InlineKeyboardButton("Cancelar", callback_data="ops"),
            ],
        ]
    )


def webcam_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("📷 Sim, fotografar", callback_data="webcam_now"),
          InlineKeyboardButton("Cancelar", callback_data="ops")]]
    )


def scan_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("🌐 Sim, escanear", callback_data="scan_now"),
          InlineKeyboardButton("Cancelar", callback_data="network_menu")]]
    )


def silence_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("30 min", callback_data="silence_30"),
                InlineKeyboardButton("1 h", callback_data="silence_60"),
                InlineKeyboardButton("3 h", callback_data="silence_180"),
            ],
            [
                InlineKeyboardButton("Cancelar silêncio", callback_data="silence_off"),
                InlineKeyboardButton("‹ Operações", callback_data="ops"),
            ],
        ]
    )


def maintenance_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("30 min", callback_data="maintenance_30"),
                InlineKeyboardButton("1 h", callback_data="maintenance_60"),
                InlineKeyboardButton("3 h", callback_data="maintenance_180"),
            ],
            [
                InlineKeyboardButton("Encerrar", callback_data="maintenance_off"),
                InlineKeyboardButton("‹ Operações", callback_data="ops"),
            ],
        ]
    )


def updates_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔎 Ver atualizações", callback_data="apt_check"),
            ],
            [
                InlineKeyboardButton("⬆️ Confirmar upgrade", callback_data="apt_upgrade_confirm"),
            ],
            [
                InlineKeyboardButton("‹ Operações", callback_data="ops"),
            ],
        ]
    )


def apt_upgrade_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("⬆️ Sim, atualizar", callback_data="apt_upgrade_now"),
          InlineKeyboardButton("Cancelar", callback_data="updates_menu")]]
    )


def status_icon(address: str) -> str:
    if address in state.account_errors:
        return "🔴"
    if address in gmail_services:
        return "🟢"
    return "🟡"


def format_uptime() -> str:
    seconds = int(time.time() - state.started_at)
    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}min"
    return f"{minutes}min"


async def unread_counts() -> dict[str, int]:
    async def read(address: str, account: dict) -> tuple[str, int]:
        try:
            count = await asyncio.to_thread(get_unread_count, account["service"])
            state.account_errors.pop(address, None)
            return address, count
        except Exception as exc:
            state.account_errors[address] = str(exc)
            return address, -1

    results = await asyncio.gather(
        *(read(address, account) for address, account in gmail_services.items())
    )
    return dict(results)


def command_output(command: list[str], timeout: int = 4) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def run_command_result(command: list[str], timeout: int = 30) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)

    detail = (result.stdout or result.stderr).strip()
    if result.returncode == 0:
        return True, detail
    if not detail:
        detail = f"codigo {result.returncode}"
    return False, detail


def config_bool(name: str, default: bool = True) -> bool:
    return bool(getattr(config, name, default))


def config_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(getattr(config, name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, value)


def actor_label(update: Update | None) -> str:
    user = update.effective_user if update else None
    if not user:
        return "sistema"
    username = f"@{user.username}" if user.username else ""
    return f"{user.id}{(' ' + username) if username else ''}"


def register_action(update: Update | None, action: str, ok: bool, detail: str) -> None:
    try:
        db.record_action(action, actor_label(update), ok, detail)
    except Exception:
        logger.exception("Falha ao registrar histórico de ação")


def pc_agent_snapshot() -> dict[str, Any] | None:
    try:
        return pc_bridge.get_agent(PC_AGENT_ID)
    except Exception:
        logger.exception("Falha ao consultar o agente do PC")
        return None


def pc_metadata() -> dict[str, Any]:
    snapshot = pc_agent_snapshot()
    if not snapshot:
        return {}
    metadata = snapshot.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def pc_is_online() -> bool:
    snapshot = pc_agent_snapshot()
    return bool(snapshot and snapshot.get("online"))


def format_age(seconds: int | float) -> str:
    value = max(0, int(seconds))
    if value < 60:
        return f"{value}s"
    minutes, seconds = divmod(value, 60)
    if minutes < 60:
        return f"{minutes}min {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}min"


def enqueue_pc_action(
    update: Update | None,
    action: str,
    payload: dict[str, Any] | None = None,
    *,
    description: str = "",
) -> dict[str, Any]:
    return pc_bridge.enqueue_job(
        action,
        payload or {},
        description=description or PC_ACTION_LABELS.get(action, action),
        requested_by=actor_label(update),
        target_agent=PC_AGENT_ID,
    )


def pc_queue_message(job: dict[str, Any]) -> str:
    job_id = str(job.get("job_id", ""))
    action = str(job.get("action", ""))
    online = pc_is_online()
    state_text = "o PC já pode executar" if online else "ficará aguardando o PC ligar"
    return (
        f"<b>📥 TAREFA ENVIADA AO PC</b>\n\n"
        f"ID: <code>{html.escape(job_id)}</code>\n"
        f"Ação: <b>{html.escape(PC_ACTION_LABELS.get(action, action))}</b>\n"
        f"Estado: <b>aguardando</b> — {state_text}.\n\n"
        "O resultado aparecerá automaticamente aqui."
    )


def now_ts() -> float:
    return time.time()


def is_silenced() -> bool:
    return now_ts() < state.silence_until or now_ts() < state.maintenance_until


def silence_reason() -> str:
    now = now_ts()
    if now < state.maintenance_until:
        return f"manutenção até {datetime.fromtimestamp(state.maintenance_until).strftime('%H:%M')}"
    if now < state.silence_until:
        return f"silenciado até {datetime.fromtimestamp(state.silence_until).strftime('%H:%M')}"
    return ""


def state_banner() -> str:
    reason = silence_reason()
    if reason:
        return f"\n🟡 <b>Modo:</b> {html.escape(reason)}\n"
    return ""


async def send_proactive_message(bot, text: str, **kwargs) -> bool:
    if is_silenced():
        state.suppressed_notifications += 1
        logger.info("Notificação suprimida: %s", silence_reason())
        return False
    await bot.send_message(chat_id=get_chat_id(), text=text, **kwargs)
    return True


async def post_action_status(update: Update, title: str, ok: bool, detail: str) -> None:
    register_action(update, title, ok, detail)
    status = await quick_status_text()
    prefix = "✅" if ok else "⚠️"
    await update.effective_message.reply_text(
        f"<b>{prefix} {html.escape(title)}</b>\n\n"
        f"<code>{html.escape(detail[:900])}</code>\n\n"
        f"{status}",
        parse_mode=ParseMode.HTML,
        reply_markup=main_keyboard(),
    )


def lock_user_sessions() -> list[str]:
    lock_user = str(getattr(config, "LOCK_USER", "") or getpass.getuser())
    sessions = command_output(
        ["loginctl", "show-user", lock_user, "-p", "Display", "--value"]
    ).split()
    sessions.extend(
        command_output(
            ["loginctl", "show-user", lock_user, "-p", "Sessions", "--value"]
        ).split()
    )
    seen_sessions = []
    for session_id in sessions:
        if session_id and session_id not in seen_sessions:
            seen_sessions.append(session_id)
    return seen_sessions


def lock_commands() -> list[list[str]]:
    command = configured_command("LOCK_COMMAND")
    if command:
        return [command]

    uid = os.getuid()
    commands = [["loginctl", "lock-session", session_id] for session_id in lock_user_sessions()]
    commands.extend(
        [
            ["loginctl", "lock-sessions"],
            [
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "qdbus6",
                "org.freedesktop.ScreenSaver",
                "/ScreenSaver",
                "Lock",
            ],
            [
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "qdbus6",
                "org.kde.screensaver",
                "/ScreenSaver",
                "Lock",
            ],
        ]
    )
    return [
        command
        for index, command in enumerate(commands)
        if command not in commands[:index]
    ]


def run_lock_command() -> tuple[bool, str]:
    return run_power_commands("bloqueio de tela", lock_commands())


def unlock_commands() -> list[list[str]]:
    command = configured_command("UNLOCK_COMMAND")
    if command:
        return [command]

    uid = os.getuid()
    commands = [["loginctl", "unlock-session", session_id] for session_id in lock_user_sessions()]
    commands.extend(
        [
            ["loginctl", "unlock-sessions"],
            [
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "qdbus6",
                "org.freedesktop.ScreenSaver",
                "/ScreenSaver",
                "SetActive",
                "false",
            ],
            [
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                "qdbus6",
                "org.kde.screensaver",
                "/ScreenSaver",
                "SetActive",
                "false",
            ],
        ]
    )
    return [
        command
        for index, command in enumerate(commands)
        if command not in commands[:index]
    ]


def run_unlock_command() -> tuple[bool, str]:
    return run_power_commands("desbloqueio de tela", unlock_commands())


def shutdown_enabled() -> bool:
    return bool(getattr(config, "REMOTE_SHUTDOWN_ENABLED", True))


def reboot_enabled() -> bool:
    return bool(getattr(config, "REMOTE_REBOOT_ENABLED", True))


def suspend_enabled() -> bool:
    return bool(getattr(config, "REMOTE_SUSPEND_ENABLED", True))


def configured_command(name: str) -> list[str] | None:
    command = getattr(config, name, None)
    if isinstance(command, str):
        command = shlex.split(command)
    if command:
        return [str(part) for part in command]
    return None


def kde_power_command(method: str) -> list[str]:
    uid = os.getuid()
    return [
        "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        "qdbus6",
        "org.kde.Shutdown",
        "/Shutdown",
        method,
    ]


def session_bus_command(*command: str) -> list[str]:
    uid = os.getuid()
    return [
        "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        *command,
    ]


def shutdown_commands() -> list[list[str]]:
    command = configured_command("SHUTDOWN_COMMAND")
    if command:
        return [command]
    return [
        ["systemctl", "poweroff"],
        kde_power_command("logoutAndShutdown"),
        ["sudo", "-n", "/usr/sbin/shutdown", "-h", "now"],
        ["/usr/sbin/shutdown", "-h", "now"],
    ]


def reboot_commands() -> list[list[str]]:
    command = configured_command("REBOOT_COMMAND")
    if command:
        return [command]
    return [
        ["systemctl", "reboot"],
        kde_power_command("logoutAndReboot"),
        ["sudo", "-n", "/usr/sbin/shutdown", "-r", "now"],
        ["/usr/sbin/shutdown", "-r", "now"],
        ["sudo", "-n", "/usr/sbin/reboot"],
        ["/usr/sbin/reboot"],
    ]


def suspend_commands() -> list[list[str]]:
    command = configured_command("SUSPEND_COMMAND")
    if command:
        return [command]
    return [
        session_bus_command(
            "qdbus6",
            "org.kde.Solid.PowerManagement",
            "/org/kde/Solid/PowerManagement/Actions/SuspendSession",
            "suspendToRam",
        ),
        ["systemctl", "suspend"],
    ]


def format_command(command: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def cleanup_enabled() -> bool:
    return bool(getattr(config, "REMOTE_CLEANUP_ENABLED", True))


def cleanup_command() -> list[str]:
    command = getattr(config, "CLEANUP_COMMAND", None)
    if isinstance(command, str):
        command = shlex.split(command)
    if not command:
        command = ["sudo", "/home/voide/Kali-Bunker-main/limpeza-semanal.sh"]
    return [str(part) for part in command]


def run_power_commands(action_name: str, commands: list[list[str]]) -> tuple[bool, str]:
    errors = []
    for command in commands:
        command_text = " ".join(shlex.quote(part) for part in command)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{command_text}: {exc}")
            continue

        if result.returncode == 0:
            return True, f"Comando de {action_name} enviado: {command_text}"
        detail = (result.stderr or result.stdout).strip() or f"codigo {result.returncode}"
        errors.append(f"{command_text}: {detail}")
    return False, "\n".join(errors)[-500:]


def run_shutdown_command() -> tuple[bool, str]:
    return run_power_commands("desligamento", shutdown_commands())


def run_reboot_command() -> tuple[bool, str]:
    return run_power_commands("reinicialização", reboot_commands())


def run_suspend_command() -> tuple[bool, str]:
    return run_power_commands("suspensão", suspend_commands())


def run_cleanup_command() -> tuple[bool, str]:
    command = cleanup_command()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1200,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)

    if result.returncode == 0:
        return True, "Comando de limpeza enviado."
    detail = (result.stderr or result.stdout).strip() or f"codigo {result.returncode}"
    return False, detail[:500]


def allowed_service(code_or_unit: str) -> tuple[str, str, str] | None:
    key = code_or_unit.upper()
    if key in SERVICE_BY_CODE:
        return SERVICE_BY_CODE[key]
    return SERVICE_BY_UNIT.get(code_or_unit)


def run_service_action(action: str, code: str) -> tuple[bool, str]:
    spec = allowed_service(code)
    if not spec:
        return False, "Serviço não permitido."
    unit, name, service_code = spec
    if action not in {"start", "stop", "restart"}:
        return False, "Ação não permitida."
    errors = []
    commands = (
        (["systemctl", "--user", action, unit],)
        if service_code in {"MAIL", "STUDY"}
        else (
            ["systemctl", action, unit],
            ["sudo", "-n", "/usr/bin/systemctl", action, unit],
        )
    )
    for command in commands:
        ok, detail = run_command_result(command, timeout=30)
        if ok:
            return True, f"{name}: {action} enviado para {unit}."
        errors.append(f"{format_command(command)}: {detail}")
    return False, "\n".join(errors)[-1000:]


def read_service_logs(code: str, lines: int = LOG_LINE_LIMIT) -> tuple[bool, str]:
    spec = allowed_service(code)
    if not spec:
        return False, "Serviço não permitido."
    unit, name, service_code = spec
    errors = []
    detail = ""
    commands = (
        (["journalctl", "--user", "-u", unit, "-n", str(lines), "--no-pager", "--output", "short-iso"],)
        if service_code in {"MAIL", "STUDY"}
        else (
            ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output", "short-iso"],
            ["sudo", "-n", "/usr/bin/journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output", "short-iso"],
        )
    )
    for command in commands:
        ok, detail = run_command_result(command, timeout=10)
        if ok:
            break
        errors.append(f"{format_command(command)}: {detail}")
    else:
        return False, "\n".join(errors)[-2500:]
    if not detail:
        detail = "Sem logs recentes."
    return True, f"{name} · {unit}\n\n{detail[-3200:]}"


def local_ips() -> list[str]:
    snapshot = pc_agent_snapshot()
    metadata = snapshot.get("metadata", {}) if snapshot and snapshot.get("online") else {}
    remote_ips = metadata.get("ips", []) if isinstance(metadata, dict) else []
    if isinstance(remote_ips, list):
        normalized = [str(value) for value in remote_ips if str(value).strip()]
        if normalized:
            return normalized
    output = command_output(["hostname", "-I"])
    return output.split() if output else []


def default_scan_target() -> str:
    configured = str(getattr(config, "NETWORK_SCAN_TARGET", "") or "").strip()
    if configured:
        return configured
    for ip in local_ips():
        parts = ip.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return ".".join(parts[:3]) + ".0/24"
    return "192.168.0.0/24"


def validate_network_target(target: str) -> bool:
    if not NETWORK_TARGET_RE.fullmatch(target):
        return False
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return network.is_private or network.is_loopback or network.is_link_local
        address = ipaddress.ip_address(target)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return False


def run_network_scan(target: str | None = None) -> tuple[bool, str]:
    selected = (target or default_scan_target()).strip()
    if not validate_network_target(selected):
        return False, "Alvo de rede inválido. Use apenas IPs ou CIDRs privados/locais."
    command = ["nmap", "-sn", selected]
    ok, detail = run_command_result(command, timeout=config_int("NETWORK_SCAN_TIMEOUT_SECONDS", 90, 10))
    if not ok:
        return False, detail[:3000]
    hosts = []
    current = ""
    for line in detail.splitlines():
        if line.startswith("Nmap scan report for "):
            current = line.replace("Nmap scan report for ", "", 1).strip()
            hosts.append(current)
        elif "MAC Address:" in line and current:
            hosts[-1] = f"{current} · {line.strip()}"
    host_lines = "\n".join(f"• {html.escape(host)}" for host in hosts[:40])
    if not host_lines:
        host_lines = html.escape(detail[-2500:])
    return True, (
        f"<b>🌐 SCAN DE REDE</b>\n\n"
        f"Alvo: <code>{html.escape(selected)}</code>\n"
        f"Hosts encontrados: <b>{len(hosts)}</b>\n\n"
        f"{host_lines}"
    )


def capture_webcam_photo() -> tuple[bool, str]:
    output_dir = Path("/tmp/kali-bunker-bot")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    photo_path = output_dir / f"webcam-{int(time.time())}.jpg"
    command = [
        "fswebcam",
        "--quiet",
        "--no-banner",
        "-r",
        str(getattr(config, "WEBCAM_RESOLUTION", "1280x720")),
        str(photo_path),
    ]
    ok, detail = run_command_result(command, timeout=20)
    if not ok:
        return False, detail[:700]
    if not photo_path.exists() or photo_path.stat().st_size == 0:
        return False, "Foto não foi gerada."
    return True, str(photo_path)


def battery_status() -> psutil._common.sbattery | None:
    try:
        return psutil.sensors_battery()
    except (AttributeError, RuntimeError):
        return None


def format_battery_line() -> str:
    battery = battery_status()
    if not battery:
        return "🔋 <b>Bateria:</b> N/D"
    plugged = "na tomada" if battery.power_plugged else "fora da tomada"
    return f"🔋 <b>Bateria:</b> {battery.percent:.0f}% · {plugged}"


def parse_temperature_value(value: str) -> float | None:
    try:
        return float(value.replace("+", "").replace("°C", "").strip())
    except ValueError:
        return None


def service_states() -> dict[str, str]:
    states: dict[str, str] = {}
    snapshot = pc_agent_snapshot()
    metadata = snapshot.get("metadata", {}) if snapshot else {}
    remote_states = metadata.get("services", {}) if isinstance(metadata, dict) else {}
    remote_online = bool(snapshot and snapshot.get("online"))
    for unit, _, code in SECURITY_SERVICES:
        if code in PC_SERVICE_CODES:
            value = remote_states.get(unit) if isinstance(remote_states, dict) else None
            states[unit] = str(value or "unknown") if remote_online else "offline"
            continue
        value = command_output(["systemctl", "--user", "is-active", unit])
        if not value:
            value = command_output(["systemctl", "is-active", unit])
        states[unit] = value or "unknown"
    return states


def bluetooth_connected() -> bool:
    if not config.IPHONE_MAC:
        return False
    output = command_output(["bluetoothctl", "info", config.IPHONE_MAC])
    return "Connected: yes" in output


def temperature() -> str:
    output = command_output(["sensors"])
    for preferred in ("Package id 0", "Tctl", "Core 0"):
        for line in output.splitlines():
            if preferred in line and ":" in line:
                return line.split(":", 1)[1].strip().split()[0]
    return "N/D"


def action_history_text(limit: int = 20) -> str:
    rows = db.get_action_history(limit)
    if not rows:
        return "<b>🧾 HISTÓRICO</b>\n\nNenhuma ação registrada ainda."
    lines = ["<b>🧾 HISTÓRICO DE AÇÕES</b>", ""]
    for row in rows:
        icon = "✅" if row["ok"] else "⚠️"
        lines.append(
            f"{icon} <b>{html.escape(row['action'])}</b>\n"
            f"    └ {html.escape(row['created_at'])} · {html.escape(row['actor'])}"
        )
    return "\n".join(lines)


def integrity_checks() -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))

    for command in ("systemctl", "journalctl", "loginctl", "nmap", "fswebcam", "sensors"):
        path = shutil.which(command)
        add(f"Comando {command}", bool(path), path or "não encontrado")

    env_path = PROJECT_DIR / ".env"
    if env_path.exists():
        mode = env_path.stat().st_mode & 0o777
        add(".env permissões", mode & 0o077 == 0, f"modo {mode:03o}; recomendado 600")
    else:
        add(".env", False, "arquivo não encontrado")

    add("Banco SQLite", os.access(db.DB_FILE.parent, os.W_OK), str(db.DB_FILE))
    add("Virtualenv", (PROJECT_DIR / "venv").exists(), str(PROJECT_DIR / "venv"))

    states = service_states()
    for unit, name, code in SECURITY_SERVICES:
        state_value = states.get(unit, "unknown")
        add(f"Serviço {code}", state_value == "active", f"{name}: {state_value}")

    disk = psutil.disk_usage("/")
    add("Disco", disk.percent < 90, f"{disk.percent:.1f}% usado")
    return checks


def integrity_text() -> str:
    checks = integrity_checks()
    lines = ["<b>✅ INTEGRIDADE</b>", ""]
    for name, ok, detail in checks:
        icon = "✅" if ok else "⚠️"
        lines.append(f"{icon} <b>{html.escape(name)}</b>\n    └ {html.escape(detail)}")
    return "\n".join(lines)


def permissions_text() -> str:
    checks = [
        ("systemctl status", ["systemctl", "is-active", "gmail-telegram-bot.service"]),
        ("journalctl", ["journalctl", "-u", "gmail-telegram-bot.service", "-n", "1", "--no-pager"]),
        ("loginctl sessão", ["loginctl", "show-user", str(getattr(config, "LOCK_USER", "voide")), "-p", "Sessions", "--value"]),
        ("nmap", ["nmap", "--version"]),
        ("fswebcam", ["fswebcam", "--version"]),
    ]
    lines = ["<b>🔐 PERMISSÕES</b>", ""]
    for name, command in checks:
        ok, detail = run_command_result(command, timeout=6)
        status = "OK" if ok else "FALHA"
        lines.append(f"{'✅' if ok else '⚠️'} <b>{html.escape(name)}</b>: {status}")
        if not ok:
            lines.append(f"    └ <code>{html.escape(detail[:180])}</code>")
    lines.append("\nAções com sudo precisam estar liberadas com NOPASSWD.")
    return "\n".join(lines)


def apt_check_updates() -> tuple[bool, str]:
    ok, list_detail = run_command_result(["apt", "list", "--upgradable"], timeout=30)
    if not ok:
        return False, list_detail[:2000]
    lines = [line for line in list_detail.splitlines() if "/" in line][:80]
    if not lines:
        return True, "Nenhum pacote atualizável encontrado."
    return True, "\n".join(lines)


def apt_upgrade() -> tuple[bool, str]:
    command = configured_command("APT_UPGRADE_COMMAND")
    if not command:
        return (
            False,
            "Upgrade desativado. Configure APT_UPGRADE_COMMAND no .env, "
            "por exemplo: sudo -n /usr/bin/apt upgrade -y",
        )
    ok, detail = run_command_result(command, timeout=1800)
    if ok:
        return True, detail[-3000:] or f"Comando executado: {format_command(command)}"
    return False, detail[-3000:]


def startup_context() -> str:
    ok, detail = run_command_result(
        ["journalctl", "-u", "gmail-telegram-bot.service", "-n", "8", "--no-pager", "--output", "short-iso"],
        timeout=8,
    )
    if not ok:
        return "Journal indisponível."
    interesting = [
        line
        for line in detail.splitlines()
        if any(word in line.lower() for word in ("started", "stopped", "failed", "error", "exception", "restart"))
    ]
    return "\n".join(interesting[-4:]) or "Sem eventos relevantes recentes."


async def bunker_dashboard_text() -> str:
    states_task = asyncio.to_thread(service_states)
    cpu_task = asyncio.to_thread(psutil.cpu_percent, 0.3)
    pc_task = asyncio.to_thread(pc_agent_snapshot)
    states, server_cpu, pc_snapshot = await asyncio.gather(states_task, cpu_task, pc_task)
    active = sum(value == "active" for value in states.values())
    failed = sum(value == "failed" for value in states.values())
    pc_online = bool(pc_snapshot and pc_snapshot.get("online"))
    metadata = pc_snapshot.get("metadata", {}) if pc_snapshot else {}
    telemetry = metadata.get("telemetry", {}) if isinstance(metadata, dict) else {}
    cpu = telemetry.get("cpu_percent", server_cpu) if pc_online else server_cpu
    ram = telemetry.get("ram_percent", psutil.virtual_memory().percent) if pc_online else psutil.virtual_memory().percent
    disk = telemetry.get("disk_percent", psutil.disk_usage("/").percent) if pc_online else psutil.disk_usage("/").percent
    pc_host = str(metadata.get("hostname", "PC Kali")) if isinstance(metadata, dict) else "PC Kali"
    health = "PROTEGIDO" if failed == 0 else "ATENÇÃO"
    icon = "🟢" if failed == 0 else "🔴"
    gmail_state = states.get("gmail-telegram-bot.service") == "active"
    return (
        "<b>🛡️ KALI SECURITY BUNKER</b>\n"
        "<i>Central unificada de proteção e monitoramento</i>\n\n"
        f"{icon} <b>Estado:</b> {health}\n"
        f"⚙️ <b>Módulos ativos:</b> {active}/{len(SECURITY_SERVICES)}\n"
        f"🚨 <b>Falhas:</b> {failed}\n"
        f"💻 <b>CPU:</b> {cpu:.1f}%\n"
        f"🧠 <b>Memória:</b> {ram:.1f}%\n"
        f"💾 <b>Disco:</b> {disk:.1f}%\n"
        f"📨 <b>Gmail:</b> {'online' if gmail_state else 'offline'}\n"
        f"🖥️ <b>Meu PC:</b> {'online' if pc_online else 'offline'}"
        f"{' · ' + html.escape(pc_host) if pc_online else ''}\n"
        f"⏱ <b>Central online:</b> {format_uptime()}\n\n"
        f"{state_banner()}"
        f"🔇 <b>Suprimidas:</b> {state.suppressed_notifications}\n\n"
        f"<code>{html.escape(socket.gethostname())}</code> · "
        f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    )


async def quick_status_text() -> str:
    states_task = asyncio.to_thread(service_states)
    cpu_task = asyncio.to_thread(psutil.cpu_percent, 0.2)
    pc_task = asyncio.to_thread(pc_agent_snapshot)
    states, server_cpu, pc_snapshot = await asyncio.gather(states_task, cpu_task, pc_task)
    failed_units = [
        unit
        for unit, value in states.items()
        if value == "failed" or value == "inactive"
    ]
    pc_online = bool(pc_snapshot and pc_snapshot.get("online"))
    metadata = pc_snapshot.get("metadata", {}) if pc_snapshot else {}
    telemetry = metadata.get("telemetry", {}) if isinstance(metadata, dict) else {}
    cpu = telemetry.get("cpu_percent", server_cpu) if pc_online else server_cpu
    ram_percent = telemetry.get("ram_percent", psutil.virtual_memory().percent) if pc_online else psutil.virtual_memory().percent
    disk_percent = telemetry.get("disk_percent", psutil.disk_usage("/").percent) if pc_online else psutil.disk_usage("/").percent
    host = str(metadata.get("hostname", socket.gethostname())) if pc_online and isinstance(metadata, dict) else socket.gethostname()
    ips = ", ".join(local_ips()[:3]) or "N/D"
    return (
        "<b>⚡ RESUMO RÁPIDO</b>\n\n"
        f"Host: <code>{html.escape(host)}</code>\n"
        f"Agente do PC: <b>{'online' if pc_online else 'offline'}</b>\n"
        f"IPs: <code>{html.escape(ips)}</code>\n"
        f"CPU: <b>{cpu:.1f}%</b>\n"
        f"RAM: <b>{ram_percent:.1f}%</b>\n"
        f"Disco: <b>{disk_percent:.1f}%</b>\n"
        f"{format_battery_line()}\n"
        f"Falhas/parados: <b>{len(failed_units)}</b>\n"
        f"Uptime da central: <b>{format_uptime()}</b>"
        f"{state_banner()}"
    )


async def report_text() -> str:
    states_task = asyncio.to_thread(service_states)
    cpu_task = asyncio.to_thread(psutil.cpu_percent, 0.5)
    states, cpu = await asyncio.gather(states_task, cpu_task)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load = psutil.getloadavg()
    temp = await asyncio.to_thread(temperature)
    connected = await asyncio.to_thread(bluetooth_connected)
    active = sum(value == "active" for value in states.values())
    failed = [
        f"{SERVICE_BY_UNIT[unit][2]}:{value}"
        for unit, value in states.items()
        if value != "active"
    ]
    top = []
    for process in psutil.process_iter(["name", "cpu_percent", "memory_percent", "pid"]):
        try:
            top.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    top.sort(key=lambda item: item.get("cpu_percent") or 0, reverse=True)
    top_lines = [
        f"• {html.escape((item.get('name') or 'desconhecido')[:24])} "
        f"CPU {item.get('cpu_percent') or 0:.1f}% · RAM {item.get('memory_percent') or 0:.1f}%"
        for item in top[:6]
    ]
    return (
        "<b>📋 RELATÓRIO KALI BUNKER</b>\n\n"
        f"Host: <code>{html.escape(socket.gethostname())}</code>\n"
        f"Gerado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
        f"Serviços ativos: <b>{active}/{len(SECURITY_SERVICES)}</b>\n"
        f"Pendências: <code>{html.escape(', '.join(failed) if failed else 'nenhuma')}</code>\n\n"
        f"CPU: <b>{cpu:.1f}%</b>\n"
        f"Carga: <b>{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}</b>\n"
        f"RAM: <b>{ram.percent:.1f}%</b> · {ram.available / 1024**3:.1f} GiB livres\n"
        f"Disco: <b>{disk.percent:.1f}%</b> · {disk.free / 1024**3:.1f} GiB livres\n"
        f"Temperatura: <b>{html.escape(temp)}</b>\n"
        f"{format_battery_line()}\n"
        f"iPhone: <b>{'conectado' if connected else 'sem conexão'}</b>\n\n"
        f"{state_banner()}"
        f"Notificações suprimidas: <b>{state.suppressed_notifications}</b>\n\n"
        "<b>Top processos</b>\n"
        + "\n".join(top_lines)
    )


async def gmail_dashboard_text() -> str:
    counts = await unread_counts()
    total_unread = sum(value for value in counts.values() if value >= 0)
    last_check = (
        state.last_check_at.strftime("%H:%M:%S")
        if state.last_check_at
        else "aguardando"
    )
    health = "OPERACIONAL" if not state.account_errors else "ATENÇÃO"
    health_icon = "🟢" if not state.account_errors else "🟠"

    lines = [
        "<b>🛡️ KALI BUNKER · GMAIL</b>",
        "<i>Central de monitoramento de mensagens</i>",
        "",
        f"{health_icon} <b>Estado:</b> {health}",
        f"📡 <b>Contas conectadas:</b> {len(gmail_services)}/{len(config.GMAIL_ACCOUNTS)}",
        f"📨 <b>Não lidas:</b> {total_unread}",
        f"🔔 <b>Notificações:</b> {state.total_notifications}",
        f"🕒 <b>Última verificação:</b> {last_check}",
        f"⏱ <b>Uptime:</b> {format_uptime()}",
        "",
        "<b>Contas</b>",
    ]
    for address, account in gmail_services.items():
        count = counts.get(address, -1)
        count_text = "erro" if count < 0 else f"{count} não lida(s)"
        lines.append(
            f"{status_icon(address)} {html.escape(account['label'])} "
            f"— <code>{html.escape(address)}</code>\n"
            f"    └ {count_text}"
        )
    return "\n".join(lines)


async def security_text() -> str:
    states = await asyncio.to_thread(service_states)
    lines = [
        "<b>🛡️ DEFESAS DO SISTEMA</b>",
        "<i>Estado em tempo real dos módulos</i>",
        "",
    ]
    for unit, name, code in SECURITY_SERVICES:
        value = states.get(unit, "unknown")
        icon = "🟢" if value == "active" else "🔴" if value == "failed" else "🟡"
        label = {
            "active": "ATIVO",
            "failed": "FALHA",
            "inactive": "PARADO",
            "unknown": "N/D",
        }.get(value, value.upper())
        lines.append(
            f"{icon} <b>{html.escape(name)}</b> <code>{code}</code>\n"
            f"    └ {label}"
        )
    return "\n".join(lines)


async def system_text() -> str:
    snapshot = await asyncio.to_thread(pc_agent_snapshot)
    if snapshot and snapshot.get("online"):
        metadata = snapshot.get("metadata", {})
        telemetry = metadata.get("telemetry", {}) if isinstance(metadata, dict) else {}
        capabilities = metadata.get("capabilities", {}) if isinstance(metadata, dict) else {}
        boot_value = telemetry.get("boot_time")
        boot_text = datetime.fromtimestamp(float(boot_value)).strftime("%d/%m %H:%M") if boot_value else "N/D"
        battery = telemetry.get("battery_percent")
        battery_text = f"{battery:.0f}%" if isinstance(battery, (int, float)) else "N/D"
        if isinstance(battery, (int, float)):
            battery_text += " · na tomada" if telemetry.get("power_plugged") else " · fora da tomada"
        return (
            "<b>💻 SAÚDE DO MEU PC</b>\n"
            "<i>Telemetria enviada pelo agente local</i>\n\n"
            f"🖥️ <b>Host:</b> <code>{html.escape(str(metadata.get('hostname', 'PC Kali')))}</code>\n"
            f"🌐 <b>IPs:</b> <code>{html.escape(', '.join(str(value) for value in metadata.get('ips', [])) or 'N/D')}</code>\n"
            f"⚙️ <b>CPU:</b> {telemetry.get('cpu_percent', 'N/D')}%\n"
            f"🧠 <b>RAM:</b> {telemetry.get('ram_percent', 'N/D')}%\n"
            f"💾 <b>Disco:</b> {telemetry.get('disk_percent', 'N/D')}%\n"
            f"🔋 <b>Bateria:</b> {html.escape(battery_text)}\n"
            f"📷 <b>Webcam:</b> {'disponível' if capabilities.get('webcam') else 'não detectada'}\n"
            f"🌐 <b>Nmap:</b> {'disponível' if capabilities.get('nmap') else 'não instalado'}\n"
            f"🕒 <b>Inicialização:</b> {boot_text}"
        )
    age = format_age(snapshot.get("age_seconds", 0)) if snapshot else "nunca conectado"
    return (
        "<b>💻 MEU PC ESTÁ OFFLINE</b>\n\n"
        f"Último contato: <b>{html.escape(age)}</b> atrás.\n"
        "O Gmail, o Telegram e a IA continuam online no servidor. "
        "As tarefas enviadas ao PC ficarão na fila."
    )


async def operations_text() -> str:
    return (
        "<b>⚙️ OPERAÇÕES REMOTAS</b>\n\n"
        "Escolha uma ação. Bloqueio, emergência, webcam e scanner pedem confirmação antes de executar."
    )


async def service_menu_text() -> str:
    states = await asyncio.to_thread(service_states)
    lines = ["<b>🧩 CONTROLE DE SERVIÇOS</b>", ""]
    for unit, name, code in SECURITY_SERVICES:
        value = states.get(unit, "unknown")
        icon = "🟢" if value == "active" else "🔴" if value == "failed" else "🟡"
        lines.append(f"{icon} <code>{code}</code> {html.escape(name)} · {html.escape(value)}")
    return "\n".join(lines)


async def service_detail_text(code: str) -> str:
    spec = allowed_service(code)
    if not spec:
        return "<b>Serviço não permitido.</b>"
    unit, name, service_code = spec
    if service_code in PC_SERVICE_CODES:
        state = service_states().get(unit, "unknown")
        enabled = "gerenciado pelo agente"
        location = "seu PC Kali"
    else:
        state = command_output(["systemctl", "--user", "is-active", unit]) or "unknown"
        enabled = command_output(["systemctl", "--user", "is-enabled", unit]) or "unknown"
        location = "servidor"
    return (
        "<b>🧩 SERVIÇO</b>\n\n"
        f"Nome: <b>{html.escape(name)}</b>\n"
        f"Código: <code>{service_code}</code>\n"
        f"Unidade: <code>{html.escape(unit)}</code>\n"
        f"Máquina: <b>{html.escape(location)}</b>\n"
        f"Estado: <b>{html.escape(state)}</b>\n"
        f"Inicialização: <b>{html.escape(enabled)}</b>"
    )


async def logs_menu_text() -> str:
    return "<b>📜 LOGS</b>\n\nEscolha um módulo para receber as últimas linhas do journal."


async def network_text() -> str:
    target = default_scan_target()
    ips = ", ".join(local_ips()[:3]) or "N/D"
    online = pc_is_online()
    return (
        "<b>🌐 REDE</b>\n\n"
        f"Agente do PC: <b>{'online' if online else 'offline'}</b>\n"
        f"IPs do PC: <code>{html.escape(ips)}</code>\n"
        f"Alvo sugerido: <code>{html.escape(target)}</code>\n\n"
        "O Nmap será executado no seu PC, onde a rede local está conectada."
    )


async def pc_panel_text() -> str:
    snapshot, counts = await asyncio.gather(
        asyncio.to_thread(pc_agent_snapshot),
        asyncio.to_thread(pc_bridge.job_counts, PC_AGENT_ID),
    )
    if not snapshot:
        return (
            "<b>🖥️ MEU PC</b>\n\n"
            "⚪ O agente ainda não se conectou ao servidor.\n\n"
            f"Tarefas aguardando: <b>{counts.get('queued', 0)}</b>\n"
            "O bot, o Gmail e a IA continuam funcionando normalmente no servidor."
        )
    metadata = snapshot.get("metadata", {})
    online = bool(snapshot.get("online"))
    telemetry = metadata.get("telemetry", {}) if isinstance(metadata, dict) else {}
    capabilities = metadata.get("capabilities", {}) if isinstance(metadata, dict) else {}
    services = metadata.get("services", {}) if isinstance(metadata, dict) else {}
    active_services = sum(value == "active" for value in services.values()) if isinstance(services, dict) else 0
    capability_names = [
        label
        for key, label in (
            ("nmap", "Nmap"),
            ("webcam", "Webcam"),
            ("ssh", "SSH"),
            ("shell", "Comandos"),
        )
        if capabilities.get(key)
    ]
    status_icon = "🟢" if online else "⚫"
    status_text = "ONLINE" if online else "OFFLINE"
    contact = "agora" if online else f"há {format_age(snapshot.get('age_seconds', 0))}"
    return (
        "<b>🖥️ MEU PC</b>\n\n"
        f"{status_icon} <b>{status_text}</b> · último contato {contact}\n"
        f"Host: <code>{html.escape(str(metadata.get('hostname', snapshot.get('hostname', 'N/D'))))}</code>\n"
        f"IPs: <code>{html.escape(', '.join(str(value) for value in metadata.get('ips', [])) or 'N/D')}</code>\n"
        f"CPU: <b>{telemetry.get('cpu_percent', 'N/D')}%</b> · "
        f"RAM: <b>{telemetry.get('ram_percent', 'N/D')}%</b> · "
        f"Disco: <b>{telemetry.get('disk_percent', 'N/D')}%</b>\n"
        f"Serviços: <b>{active_services}/{len(services) if isinstance(services, dict) else 0}</b> ativos\n"
        f"Recursos: <code>{html.escape(', '.join(capability_names) or 'N/D')}</code>\n\n"
        f"⏳ Aguardando: <b>{counts.get('queued', 0)}</b> · "
        f"⚙️ Executando: <b>{counts.get('running', 0)}</b> · "
        f"❌ Falhas: <b>{counts.get('failed', 0)}</b>"
    )


def pc_jobs_text(jobs: list[dict[str, Any]]) -> str:
    if not jobs:
        return "<b>📋 TAREFAS DO PC</b>\n\nNenhuma tarefa enviada ainda."
    labels = {
        "queued": ("⏳", "aguardando"),
        "running": ("⚙️", "executando"),
        "completed": ("✅", "concluída"),
        "failed": ("❌", "falhou"),
        "canceled": ("🚫", "cancelada"),
    }
    lines = ["<b>📋 TAREFAS DO PC</b>", ""]
    for job in jobs:
        status = str(job.get("status", ""))
        icon, status_label = labels.get(status, ("•", status))
        action = PC_ACTION_LABELS.get(str(job.get("action", "")), str(job.get("action", "")))
        created = datetime.fromtimestamp(float(job.get("created_at", 0))).strftime("%d/%m %H:%M")
        lines.append(
            f"{icon} <code>{html.escape(str(job.get('job_id', '')))}</code> · "
            f"<b>{html.escape(action)}</b>\n"
            f"    └ {html.escape(status_label)} · {created}"
        )
    return "\n".join(lines)


def pc_job_text(job: dict[str, Any]) -> str:
    status_labels = {
        "queued": "⏳ aguardando o PC",
        "running": "⚙️ executando",
        "completed": "✅ concluída",
        "failed": "❌ falhou",
        "canceled": "🚫 cancelada",
    }
    action = str(job.get("action", ""))
    payload = job.get("payload", {}) if isinstance(job.get("payload"), dict) else {}
    preview = payload.get("command") or payload.get("target") or payload.get("path") or ""
    result = str(job.get("result_text", ""))[-2200:]
    text = (
        "<b>📋 DETALHE DA TAREFA</b>\n\n"
        f"ID: <code>{html.escape(str(job.get('job_id', '')))}</code>\n"
        f"Ação: <b>{html.escape(PC_ACTION_LABELS.get(action, action))}</b>\n"
        f"Estado: <b>{html.escape(status_labels.get(str(job.get('status', '')), str(job.get('status', ''))))}</b>\n"
        f"Descrição: {html.escape(str(job.get('description', '')))}"
    )
    if preview:
        text += f"\nPedido: <code>{html.escape(str(preview)[:800])}</code>"
    if result:
        text += f"\n\n<b>Resultado</b>\n<code>{html.escape(result)}</code>"
    if job.get("cancel_requested") and str(job.get("status")) == "running":
        text += "\n\n🛑 Cancelamento solicitado; aguardando o agente parar o processo."
    return text


async def accounts_text() -> str:
    counts = await unread_counts()
    lines = ["<b>📬 CONTAS MONITORADAS</b>", ""]
    for index, account in enumerate(config.GMAIL_ACCOUNTS, start=1):
        address = account.get("email", "")
        count = counts.get(address, -1)
        state_text = "conectada" if address in gmail_services else "indisponível"
        count_text = "N/D" if count < 0 else str(count)
        lines.extend(
            [
                f"<b>{index}. {html.escape(account_label(account))}</b>",
                f"<code>{html.escape(address)}</code>",
                f"{status_icon(address)} {state_text} · {count_text} não lida(s)",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def stats_text() -> str:
    stats = db.get_stats()
    total_seen = sum(stats.values())
    last_check = (
        state.last_check_at.strftime("%d/%m/%Y às %H:%M:%S")
        if state.last_check_at
        else "ainda não realizada"
    )
    lines = [
        "<b>📈 ESTATÍSTICAS</b>",
        "",
        f"🔎 <b>Verificações nesta execução:</b> {state.checks_completed}",
        f"🔔 <b>Notificações nesta execução:</b> {state.total_notifications}",
        f"🗃 <b>Mensagens registradas:</b> {total_seen}",
        f"⚡ <b>Duração da última busca:</b> {state.last_check_duration:.1f}s",
        f"🕒 <b>Última busca:</b> {last_check}",
        "",
        "<b>Histórico por conta</b>",
    ]
    for account in config.GMAIL_ACCOUNTS:
        address = account.get("email", "")
        lines.append(
            f"• {html.escape(account_label(account))}: {stats.get(address, 0)} notificação(ões)"
        )
    return "\n".join(lines)


def help_text() -> str:
    return (
        "<b>ℹ️ CENTRAL KALI BUNKER</b>\n\n"
        "Este bot reúne os módulos de segurança, telemetria do computador "
        "e monitoramento Gmail em uma única interface.\n\n"
        "<b>Comandos disponíveis</b>\n"
        "/painel — central principal\n"
        "/seguranca — estado das defesas\n"
        "/sistema — CPU, memória, disco e Bluetooth\n"
        "/pc — conexão, recursos e telemetria do seu PC\n"
        "/tarefas — fila e histórico de tarefas do PC\n"
        "/cancelar ID — cancela uma tarefa aguardando ou executando\n"
        "/ia pedido — conversa ou prepara uma ação no seu PC\n"
        "/gmail — painel de mensagens\n"
        "/contas — lista as contas\n"
        "/verificar — busca novos e-mails agora\n"
        "/resumo — status rápido do sistema\n"
        "/relatorio — relatório completo\n"
        "/servicos — controle dos módulos\n"
        "/servico WIFI restart — controla um módulo\n"
        "/logs AUTH — últimas linhas de um módulo\n"
        "/scan — escaneia a rede local a partir do seu PC\n"
        "/bloquear — bloqueia a tela\n"
        "/desbloquear — desbloqueia a tela\n"
        "/emergencia — bloqueia e reinicia módulos críticos\n"
        "/silenciar — pausa alertas\n"
        "/manutencao — ativa modo manutenção\n"
        "/integridade — checagem do bot\n"
        "/permissoes — checa permissões\n"
        "/historico — últimas ações remotas\n"
        "/atualizar — menu de atualização\n"
        "/webcam — tira foto da webcam do PC com confirmação\n"
        "/desligar — abre confirmação para desligar o PC\n"
        "/reiniciar — abre confirmação para reiniciar o PC\n"
        "/suspender — abre confirmação para suspender o PC\n"
        "/limpeza — abre confirmação para limpar o sistema\n"
        "/ajuda — mostra esta ajuda"
    )


async def edit_or_reply(
    update: Update,
    text: str,
    keyboard: InlineKeyboardMarkup,
) -> None:
    query = update.callback_query
    if query:
        try:
            await query.edit_message_text(
                text=text,
                parse_mode=ParseMode.HTML,
                reply_markup=keyboard,
                disable_web_page_preview=True,
            )
        except BadRequest as exc:
            message = str(exc)
            if "Message is not modified" in message:
                return
            if "There is no text in the message to edit" not in message:
                raise
            if query.message:
                await query.message.reply_text(
                    text=text,
                    parse_mode=ParseMode.HTML,
                    reply_markup=keyboard,
                    disable_web_page_preview=True,
                )
        return
    await update.effective_message.reply_text(
        text=text,
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
        disable_web_page_preview=True,
    )


async def answer_callback(query, *args, **kwargs) -> None:
    if not query:
        return
    try:
        await query.answer(*args, **kwargs)
    except BadRequest as exc:
        if "Query is too old" not in str(exc):
            raise


async def edit_query_or_reply(query, text: str, keyboard: InlineKeyboardMarkup) -> None:
    try:
        await query.edit_message_text(
            text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
    except BadRequest as exc:
        message = str(exc)
        if "Message is not modified" in message:
            return
        if "There is no text in the message to edit" not in message:
            raise
        if query.message:
            await query.message.reply_text(
                text,
                parse_mode=ParseMode.HTML,
                reply_markup=keyboard,
            )


async def send_notification(bot, account: dict, email: dict) -> None:
    summary = await asyncio.to_thread(
        summarize_email,
        email["sender"],
        email["subject"],
        email["body"],
        email["snippet"],
    )
    gmail_url = f"https://mail.google.com/mail/u/?authuser={account['email']}#inbox"
    message = (
        "<b>📨 NOVO E-MAIL IMPORTANTE</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        f"{html.escape(account['label'])} · "
        f"<code>{html.escape(account['email'])}</code>\n\n"
        f"<b>De</b>\n{html.escape(email['sender'][:100])}\n\n"
        f"<b>Assunto</b>\n{html.escape(email['subject'][:160])}\n\n"
        f"<b>Resumo</b>\n{html.escape(summary[:700])}"
    )
    keyboard = InlineKeyboardMarkup(
        [[InlineKeyboardButton("Abrir caixa de entrada ↗", url=gmail_url)]]
    )
    await send_proactive_message(
        bot,
        text=message,
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
        disable_web_page_preview=True,
    )


async def check_emails(bot) -> dict[str, int]:
    if check_lock.locked():
        return {"new": 0, "filtered": 0, "errors": 0, "busy": 1}

    async with check_lock:
        started = time.monotonic()
        result = {"new": 0, "filtered": 0, "errors": 0, "busy": 0}
        if not gmail_services:
            await asyncio.to_thread(init_gmail_services)

        for address, account in list(gmail_services.items()):
            try:
                emails = await asyncio.to_thread(
                    get_unread_emails,
                    account["service"],
                    config.MAX_EMAILS_PER_CHECK,
                )
                state.account_errors.pop(address, None)
                for email in emails:
                    if not is_important_email(email):
                        result["filtered"] += 1
                        continue
                    if db.is_seen(address, email["id"]):
                        continue
                    await send_notification(bot, account, email)
                    db.mark_seen(address, email["id"])
                    result["new"] += 1
                    state.total_notifications += 1
                    await asyncio.sleep(0.4)
            except Exception as exc:
                result["errors"] += 1
                state.account_errors[address] = str(exc)
                logger.exception("Erro ao verificar %s", address)

        state.last_check_at = datetime.now()
        state.last_check_duration = time.monotonic() - started
        state.last_new_emails = result["new"]
        state.checks_completed += 1
        logger.info(
            "Verificação concluída: %s novo(s), %s filtrado(s), %s erro(s), %.1fs",
            result["new"],
            result["filtered"],
            result["errors"],
            state.last_check_duration,
        )
        return result


async def show_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await bunker_dashboard_text(), main_keyboard())


async def show_gmail(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await gmail_dashboard_text(), gmail_keyboard())


async def show_security(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await security_text(), back_keyboard())


async def show_system(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await system_text(), back_keyboard())


async def show_pc_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await pc_panel_text(), pc_keyboard())


async def show_ai_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🤖 VOZ IA</b>\n\n"
        "Pode escrever normalmente, sem comando. Eu converso, explico, preparo comandos, "
        "faço Nmap, acesso máquinas por SSH, controlo serviços e peço foto ao seu PC.\n\n"
        "Quando houver uma ação real, você verá primeiro o que será feito e confirmará. "
        "Depois, acompanhe em <b>Tarefas</b>.",
        pc_keyboard(),
    )


async def show_pc_jobs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    jobs = await asyncio.to_thread(pc_bridge.list_jobs, target_agent=PC_AGENT_ID, limit=12)
    await edit_or_reply(update, pc_jobs_text(jobs), pc_jobs_keyboard(jobs))


async def show_pc_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    job_id: str,
) -> None:
    if not allowed(update):
        return
    try:
        job = await asyncio.to_thread(pc_bridge.get_job, job_id)
    except ValueError:
        job = None
    if not job:
        await edit_or_reply(update, "Tarefa não encontrada.", pc_keyboard())
        return
    await edit_or_reply(update, pc_job_text(job), pc_job_keyboard(job))


async def cancel_pc_job(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    job_id: str,
) -> None:
    if not allowed(update):
        return
    try:
        job = await asyncio.to_thread(pc_bridge.cancel_job, job_id)
    except ValueError:
        job = None
    if not job:
        await edit_or_reply(update, "Tarefa não encontrada.", pc_keyboard())
        return
    register_action(update, "Cancelar tarefa do PC", True, f"Tarefa {job_id}: {job['status']}")
    await edit_or_reply(update, pc_job_text(job), pc_job_keyboard(job))


async def manual_cancel_pc_job(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not context.args:
        await update.effective_message.reply_text("Uso: /cancelar ID_DA_TAREFA")
        return
    await cancel_pc_job(update, context, context.args[0])


async def queue_pc_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    job = await asyncio.to_thread(
        enqueue_pc_action,
        update,
        "status",
        {},
        description="Atualizar telemetria e testar a conexão com o PC",
    )
    register_action(update, "Status do PC", True, f"Tarefa {job['job_id']} enfileirada")
    await update.effective_message.reply_text(
        pc_queue_message(job),
        parse_mode=ParseMode.HTML,
        reply_markup=pc_job_keyboard(job),
    )


async def queue_confirmed_pc_action(
    update: Update,
    action: str,
    payload: dict[str, Any] | None = None,
    *,
    description: str,
) -> dict[str, Any]:
    job = await asyncio.to_thread(
        enqueue_pc_action,
        update,
        action,
        payload or {},
        description=description,
    )
    register_action(update, PC_ACTION_LABELS.get(action, action), True, f"Tarefa {job['job_id']} enfileirada")
    await edit_or_reply(update, pc_queue_message(job), pc_job_keyboard(job))
    return job


async def show_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await accounts_text(), back_keyboard())


async def show_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, stats_text(), back_keyboard())


async def show_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, help_text(), back_keyboard())


async def show_operations(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await operations_text(), operations_keyboard())


async def show_silence_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🔕 SILENCIAR ALERTAS</b>\n\n"
        "Pausa notificações proativas do bot. Comandos manuais continuam respondendo.",
        silence_keyboard(),
    )


async def set_silence(update: Update, context: ContextTypes.DEFAULT_TYPE, minutes: int) -> None:
    if not allowed(update):
        return
    if minutes <= 0:
        state.silence_until = 0
        detail = "Silêncio cancelado."
        ok = True
    else:
        state.silence_until = now_ts() + minutes * 60
        detail = f"Alertas silenciados por {minutes} min."
        ok = True
    await post_action_status(update, "Silenciar alertas", ok, detail)


async def show_maintenance_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🛠️ MODO MANUTENÇÃO</b>\n\n"
        "Pausa alertas proativos e marca o painel como manutenção.",
        maintenance_keyboard(),
    )


async def set_maintenance(update: Update, context: ContextTypes.DEFAULT_TYPE, minutes: int) -> None:
    if not allowed(update):
        return
    if minutes <= 0:
        state.maintenance_until = 0
        detail = "Modo manutenção encerrado."
    else:
        state.maintenance_until = now_ts() + minutes * 60
        detail = f"Modo manutenção ativo por {minutes} min."
    await post_action_status(update, "Modo manutenção", True, detail)


async def show_quick_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await quick_status_text(), main_keyboard())


async def show_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await report_text(), main_keyboard())


async def show_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, action_history_text(), operations_keyboard())


async def show_integrity(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await asyncio.to_thread(integrity_text), operations_keyboard())


async def show_permissions(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await asyncio.to_thread(permissions_text), operations_keyboard())


async def show_updates_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>⬆️ ATUALIZAÇÃO DO SISTEMA</b>\n\n"
        "Primeiro veja os pacotes atualizáveis. Upgrade só roda depois de confirmação.",
        updates_keyboard(),
    )


async def apt_check_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, "<b>🔎 VERIFICANDO ATUALIZAÇÕES</b>\n\nAguarde.", updates_keyboard())
    ok, detail = await asyncio.to_thread(apt_check_updates)
    register_action(update, "Ver atualizações", ok, detail)
    await update.effective_message.reply_text(
        ("<b>⬆️ PACOTES ATUALIZÁVEIS</b>\n\n" if ok else "<b>Falha ao verificar atualizações.</b>\n\n")
        + f"<code>{html.escape(detail[-3500:])}</code>",
        parse_mode=ParseMode.HTML,
        reply_markup=updates_keyboard(),
    )


async def show_apt_upgrade_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>⬆️ EXECUTAR UPGRADE?</b>\n\n"
        "Confirme para rodar <code>apt upgrade -y</code>.",
        apt_upgrade_keyboard(),
    )


async def apt_upgrade_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if system_action_lock.locked():
        await edit_or_reply(update, "Uma ação de sistema já está em andamento.", updates_keyboard())
        return
    await edit_or_reply(update, "<b>⬆️ UPGRADE EM ANDAMENTO</b>\n\nIsso pode demorar.", updates_keyboard())
    async with system_action_lock:
        ok, detail = await asyncio.to_thread(apt_upgrade)
    await post_action_status(update, "Upgrade do sistema", ok, detail)


async def show_services(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await service_menu_text(), service_menu_keyboard())


async def show_service_detail(update: Update, context: ContextTypes.DEFAULT_TYPE, code: str) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await service_detail_text(code), service_action_keyboard(code))


async def show_service_confirm(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    action: str,
    code: str,
) -> None:
    if not allowed(update):
        return
    spec = allowed_service(code)
    if not spec:
        await edit_or_reply(update, "Serviço não permitido.", service_menu_keyboard())
        return
    _, name, service_code = spec
    labels = {
        "restart": "reiniciar",
        "start": "iniciar",
        "stop": "parar",
    }
    if action == "stop" and service_code == "MAIL":
        await edit_or_reply(
            update,
            "Parar o próprio bot pelo Telegram foi bloqueado para não cortar o acesso remoto.",
            service_action_keyboard(service_code),
        )
        return
    await edit_or_reply(
        update,
        f"<b>🧩 CONFIRMAR SERVIÇO</b>\n\n"
        f"Deseja {labels[action]} <b>{html.escape(name)}</b>?",
        service_confirm_keyboard(action, service_code),
    )


async def service_action_now(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    action: str,
    code: str,
) -> None:
    if not allowed(update):
        return
    query = update.callback_query
    if system_action_lock.locked():
        await edit_or_reply(update, "Uma ação de sistema já está em andamento.", service_menu_keyboard())
        return
    if action == "stop" and code == "MAIL":
        await edit_or_reply(update, "Parar o bot por aqui está bloqueado.", service_action_keyboard(code))
        return

    if code in PC_SERVICE_CODES:
        job = await asyncio.to_thread(
            enqueue_pc_action,
            update,
            "service",
            {"service_action": action, "service_code": code},
            description=f"{action} do serviço {code} no PC",
        )
        register_action(update, f"Serviço {action} {code}", True, f"Tarefa {job['job_id']} enfileirada")
        await edit_or_reply(update, pc_queue_message(job), pc_job_keyboard(job))
        return

    await edit_or_reply(
        update,
        "<b>🧩 AÇÃO SOLICITADA</b>\n\nExecutando comando do systemd.",
        service_action_keyboard(code),
    )
    async with system_action_lock:
        ok, detail = await asyncio.to_thread(run_service_action, action, code)
    await post_action_status(update, f"Serviço {action} {code}", ok, detail)


async def manual_service(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if len(context.args) < 2:
        await update.effective_message.reply_text(
            "Uso: /servico WIFI restart\nAções: start, stop, restart",
            reply_markup=service_menu_keyboard(),
        )
        return
    code = context.args[0].upper()
    action = context.args[1].lower()
    if action not in {"start", "stop", "restart"}:
        await update.effective_message.reply_text("Ação inválida. Use start, stop ou restart.")
        return
    if action == "stop" and code == "MAIL":
        await update.effective_message.reply_text("Parar o próprio bot por aqui está bloqueado.")
        return
    if system_action_lock.locked():
        await update.effective_message.reply_text("Uma ação de sistema já está em andamento.")
        return
    if code in PC_SERVICE_CODES:
        job = await asyncio.to_thread(
            enqueue_pc_action,
            update,
            "service",
            {"service_action": action, "service_code": code},
            description=f"{action} do serviço {code} no PC",
        )
        register_action(update, f"Serviço {action} {code}", True, f"Tarefa {job['job_id']} enfileirada")
        await update.effective_message.reply_text(
            pc_queue_message(job),
            parse_mode=ParseMode.HTML,
            reply_markup=pc_job_keyboard(job),
        )
        return
    async with system_action_lock:
        ok, detail = await asyncio.to_thread(run_service_action, action, code)
    await post_action_status(update, f"Serviço {action} {code}", ok, detail)


async def show_logs_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await logs_menu_text(), logs_menu_keyboard())


async def show_logs(update: Update, context: ContextTypes.DEFAULT_TYPE, code: str) -> None:
    if not allowed(update):
        return
    lines = LOG_LINE_LIMIT
    if context.args and len(context.args) > 1:
        try:
            lines = max(1, min(int(context.args[1]), 300))
        except ValueError:
            lines = LOG_LINE_LIMIT
    normalized_code = code.upper()
    if normalized_code in PC_SERVICE_CODES:
        job = await asyncio.to_thread(
            enqueue_pc_action,
            update,
            "service_logs",
            {"service_code": normalized_code, "lines": lines},
            description=f"Ler as últimas {lines} linhas do serviço {normalized_code} no PC",
        )
        register_action(update, f"Logs {normalized_code}", True, f"Tarefa {job['job_id']} enfileirada")
        await update.effective_message.reply_text(
            pc_queue_message(job),
            parse_mode=ParseMode.HTML,
            reply_markup=pc_job_keyboard(job),
        )
        return
    ok, detail = await asyncio.to_thread(read_service_logs, code, lines)
    title = "<b>📜 LOGS</b>\n\n" if ok else "<b>Falha ao ler logs.</b>\n\n"
    await edit_or_reply(
        update,
        title + f"<code>{html.escape(detail)}</code>",
        logs_menu_keyboard(),
    )


async def manual_logs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    code = context.args[0] if context.args else "AUTH"
    await show_logs(update, context, code)


async def show_network(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(update, await network_text(), network_keyboard())


async def show_scan_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🌐 ESCANEAR REDE?</b>\n\n"
        "O PC detectará automaticamente a rede conectada e usará <code>nmap -sn</code>. "
        "Se ele estiver desligado, o pedido ficará aguardando na fila.",
        scan_keyboard(),
    )


async def scan_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    job = await asyncio.to_thread(
        enqueue_pc_action,
        update,
        "network_scan",
        {},
        description="Escanear automaticamente a rede local do PC",
    )
    register_action(update, "Scan de rede", True, f"Tarefa {job['job_id']} enfileirada no PC")
    await edit_or_reply(update, pc_queue_message(job), pc_job_keyboard(job))


async def manual_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    target = context.args[0] if context.args else None
    if target and not validate_network_target(target):
        await update.effective_message.reply_text(
            "Alvo inválido. Use um IPv4 ou CIDR local, por exemplo <code>192.168.1.0/24</code>.",
            parse_mode=ParseMode.HTML,
        )
        return
    payload = {"target": target} if target else {}
    job = await asyncio.to_thread(
        enqueue_pc_action,
        update,
        "network_scan",
        payload,
        description=f"Escanear a rede {target or 'local detectada pelo PC'}",
    )
    register_action(update, "Scan de rede", True, f"Tarefa {job['job_id']} enfileirada no PC")
    await update.effective_message.reply_text(
        pc_queue_message(job),
        parse_mode=ParseMode.HTML,
        reply_markup=pc_job_keyboard(job),
    )


async def show_lock_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🔒 BLOQUEAR TELA?</b>\n\nConfirme para travar as sessões locais agora.",
        lock_keyboard(),
    )


async def lock_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await queue_confirmed_pc_action(
        update,
        "lock",
        description="Bloquear a tela e as sessões do PC",
    )


async def show_unlock_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🔓 DESBLOQUEAR TELA?</b>\n\n"
        "Confirme apenas se você confia no ambiente físico ao redor da máquina.",
        unlock_keyboard(),
    )


async def unlock_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await queue_confirmed_pc_action(
        update,
        "unlock",
        description="Desbloquear as sessões do PC",
    )


async def show_emergency_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>🚨 MODO EMERGÊNCIA?</b>\n\n"
        "Vai bloquear a tela e reiniciar os módulos principais: BT, AUTH, SYS, WIFI e FILE.",
        emergency_keyboard(),
    )


def run_emergency(include_cleanup: bool = False) -> tuple[bool, str]:
    details = []
    lock_ok, lock_detail = run_lock_command()
    details.append(f"bloqueio={'ok' if lock_ok else 'falha'}: {lock_detail}")
    ok_all = lock_ok
    for code in CORE_SECURITY_CODES:
        ok, detail = run_service_action("restart", code)
        ok_all = ok_all and ok
        details.append(f"{code}={'ok' if ok else 'falha'}: {detail}")
    if include_cleanup:
        ok, detail = run_cleanup_command()
        ok_all = ok_all and ok
        details.append(f"limpeza={'ok' if ok else 'falha'}: {detail}")
    return ok_all, "\n".join(details)[-3000:]


async def emergency_now(update: Update, context: ContextTypes.DEFAULT_TYPE, include_cleanup: bool = False) -> None:
    if not allowed(update):
        return
    await queue_confirmed_pc_action(
        update,
        "emergency",
        {"include_cleanup": include_cleanup},
        description="Bloquear o PC e reiniciar os módulos principais"
        + (" com limpeza" if include_cleanup else ""),
    )


async def show_webcam_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    await edit_or_reply(
        update,
        "<b>📷 TIRAR FOTO?</b>\n\n"
        "Confirme para enviar a tarefa à webcam do seu PC. "
        "Se ele estiver desligado, ela será executada quando o agente voltar.",
        webcam_keyboard(),
    )


async def ai_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Conversa com a IA mais recente do Kali Bunker."""
    if not allowed(update):
        return
    prompt = " ".join(context.args).strip()
    if not prompt:
        await update.effective_message.reply_text(
            "Uso: /ia sua pergunta\nExemplo: /ia explique o estado do meu sistema"
        )
        return
    if ai_assistant is None:
        await update.effective_message.reply_text("A IA do Kali Bunker não está disponível.")
        return
    chat_id = str(update.effective_chat.id) if update.effective_chat else None
    try:
        plan = await asyncio.to_thread(ai_assistant, prompt, chat_id)
        action = str(plan.get("action", "chat"))
        if action == "chat":
            answer = str(plan.get("response", "Não consegui gerar uma resposta."))
        elif action == "status":
            await update.effective_message.reply_text(
                await pc_panel_text(),
                parse_mode=ParseMode.HTML,
                reply_markup=pc_keyboard(),
            )
            return
        else:
            if create_pending is None:
                raise RuntimeError("módulo de ações remotas indisponível")
            payload: dict[str, str] = {}
            if action == "shell":
                payload = {"command": str(plan.get("command", "")).strip()}
            elif action == "send_path":
                payload = {"path": str(plan.get("path", "")).strip()}
            elif action == "install_package":
                payload = {"package": str(plan.get("package", "")).strip()}
            elif action == "service":
                payload = {
                    "service_action": str(plan.get("service_action", "")).strip(),
                    "service_code": str(plan.get("service_code", "")).strip(),
                }
            elif action in {"network_scan", "webcam"}:
                payload = {}
            else:
                raise RuntimeError(f"ação não suportada pelo painel: {action}")
            description = str(plan.get("explanation", f"Ação preparada: {action}"))
            code = create_pending(
                chat_id,
                action,
                payload,
                description,
                user_id=str(update.effective_user.id) if update.effective_user else None,
            )
            preview = payload.get("command") or payload.get("path") or description
            await update.effective_message.reply_text(
                f"⚠️ A IA preparou uma ação:\n\n{preview[:1800]}\n\nConfirma a execução?",
                reply_markup=InlineKeyboardMarkup(
                    [[
                        InlineKeyboardButton("✅ Executar", callback_data=f"ai_exec_{code}"),
                        InlineKeyboardButton("❌ Cancelar", callback_data=f"ai_cancel_{code}"),
                    ]]
                ),
            )
            return
        await update.effective_message.reply_text(answer[:3900])
    except Exception as exc:
        logger.exception("Falha na IA do Kali Bunker")
        await update.effective_message.reply_text(f"Falha ao consultar a IA: {exc}")


async def execute_ai_pending(update: Update, context: ContextTypes.DEFAULT_TYPE, code: str) -> None:
    if pop_pending is None or not update.effective_chat:
        return
    item = pop_pending(
        str(update.effective_chat.id),
        code,
        user_id=str(update.effective_user.id) if update.effective_user else None,
    )
    if not item:
        await update.effective_message.reply_text("Ação inexistente, expirada ou não autorizada.")
        return
    action = str(item["action"])
    payload = dict(item["payload"])
    try:
        if action not in {
            "shell",
            "network_scan",
            "webcam",
            "service",
            "send_path",
            "install_package",
        }:
            await update.effective_message.reply_text("Ação reconhecida, mas ainda não possui executor neste painel.")
            return
        job = await asyncio.to_thread(
            enqueue_pc_action,
            update,
            action,
            payload,
            description=str(item.get("description", PC_ACTION_LABELS.get(action, action))),
        )
        register_action(
            update,
            f"IA · {PC_ACTION_LABELS.get(action, action)}",
            True,
            f"Tarefa {job['job_id']} enviada ao PC",
        )
        await update.effective_message.reply_text(
            pc_queue_message(job),
            parse_mode=ParseMode.HTML,
            reply_markup=pc_job_keyboard(job),
        )
    except Exception as exc:
        logger.exception("Falha ao executar ação da IA")
        await update.effective_message.reply_text(f"Não foi possível enviar a tarefa ao PC: {exc}")


async def cancel_ai_pending(update: Update, context: ContextTypes.DEFAULT_TYPE, code: str) -> None:
    if cancel_pending is not None and update.effective_chat:
        cancel_pending(
            str(update.effective_chat.id),
            code,
            user_id=str(update.effective_user.id) if update.effective_user else None,
        )
    await update.effective_message.reply_text("Ação cancelada.")


async def ai_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Envia mensagens comuns para a Voz, sem exigir /ia."""
    if not allowed(update) or not update.effective_message:
        return
    prompt = (update.effective_message.text or "").strip()
    if not prompt:
        return
    context.args = prompt.split()
    await ai_command(update, context)


async def webcam_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    job = await asyncio.to_thread(
        enqueue_pc_action,
        update,
        "webcam",
        {},
        description="Capturar uma foto usando a webcam do PC",
    )
    register_action(update, "Webcam", True, f"Tarefa {job['job_id']} enfileirada no PC")
    await edit_or_reply(update, pc_queue_message(job), pc_job_keyboard(job))


async def show_shutdown_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not shutdown_enabled():
        await edit_or_reply(
            update,
            "<b>⏻ DESLIGAMENTO REMOTO</b>\n\n"
            "O desligamento remoto está desativado em <code>REMOTE_SHUTDOWN_ENABLED</code>.",
            back_keyboard(),
        )
        return

    await edit_or_reply(
        update,
        "<b>⏻ DESLIGAR MEU PC?</b>\n\n"
        "O agente local agendará o desligamento do seu PC para daqui a 1 minuto. "
        "O servidor, o Gmail e o Telegram continuarão online.",
        shutdown_keyboard(),
    )


async def show_reboot_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not reboot_enabled():
        await edit_or_reply(
            update,
            "<b>↻ REINICIALIZAÇÃO REMOTA</b>\n\n"
            "A reinicialização remota está desativada em <code>REMOTE_REBOOT_ENABLED</code>.",
            back_keyboard(),
        )
        return

    await edit_or_reply(
        update,
        "<b>↻ REINICIAR MEU PC?</b>\n\n"
        "O agente local agendará a reinicialização do seu PC para daqui a 1 minuto. "
        "O bot continuará online no servidor.",
        reboot_keyboard(),
    )


async def show_suspend_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not suspend_enabled():
        await edit_or_reply(
            update,
            "<b>⏾ SUSPENSÃO REMOTA</b>\n\n"
            "A suspensão remota está desativada em <code>REMOTE_SUSPEND_ENABLED</code>.",
            back_keyboard(),
        )
        return

    await edit_or_reply(
        update,
        "<b>⏾ SUSPENDER MEU PC?</b>\n\n"
        "O agente local agendará a suspensão do PC e enviará o resultado antes disso.",
        suspend_keyboard(),
    )


async def show_cleanup_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not cleanup_enabled():
        await edit_or_reply(
            update,
            "<b>🧹 LIMPEZA REMOTA</b>\n\n"
            "A limpeza remota está desativada em <code>REMOTE_CLEANUP_ENABLED</code>.",
            back_keyboard(),
        )
        return

    await edit_or_reply(
        update,
        "<b>🧹 EXECUTAR LIMPEZA AGORA?</b>\n\n"
        "Confirme para executar a limpeza do Kali Bunker no seu PC.",
        cleanup_keyboard(),
    )


async def shutdown_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not shutdown_enabled():
        await edit_or_reply(
            update,
            "Desligamento remoto desativado.",
            back_keyboard(),
        )
        return
    await queue_confirmed_pc_action(
        update,
        "shutdown",
        description="Agendar o desligamento do PC para daqui a 1 minuto",
    )


async def reboot_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not reboot_enabled():
        await edit_or_reply(
            update,
            "Reinicialização remota desativada.",
            back_keyboard(),
        )
        return
    await queue_confirmed_pc_action(
        update,
        "reboot",
        description="Agendar a reinicialização do PC para daqui a 1 minuto",
    )


async def suspend_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not suspend_enabled():
        await edit_or_reply(
            update,
            "Suspensão remota desativada.",
            back_keyboard(),
        )
        return
    await queue_confirmed_pc_action(
        update,
        "suspend",
        description="Agendar a suspensão do PC",
    )


async def cleanup_now(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    if not cleanup_enabled():
        await edit_or_reply(
            update,
            "Limpeza remota desativada.",
            back_keyboard(),
        )
        return
    await queue_confirmed_pc_action(
        update,
        "cleanup",
        description="Executar a limpeza semanal do Kali Bunker no PC",
    )


async def manual_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not allowed(update):
        return
    query = update.callback_query
    if check_lock.locked():
        if query:
            await answer_callback(query, "Uma verificação já está em andamento.", show_alert=True)
        else:
            await update.effective_message.reply_text("Uma verificação já está em andamento.")
        return

    if query:
        await edit_query_or_reply(
            query,
            "<b>🔄 VERIFICANDO AS CONTAS...</b>\n\n"
            "Consultando mensagens novas. O painel continua responsivo.",
            main_keyboard(),
        )
    else:
        progress = await update.effective_message.reply_text("🔄 Verificando as contas...")

    result = await check_emails(context.bot)
    report = (
        "<b>✅ VERIFICAÇÃO CONCLUÍDA</b>\n\n"
        f"📨 Novos importantes: <b>{result['new']}</b>\n"
        f"🧹 Filtrados: <b>{result['filtered']}</b>\n"
        f"⚠️ Erros: <b>{result['errors']}</b>\n"
        f"⚡ Tempo: <b>{state.last_check_duration:.1f}s</b>"
    )
    if query:
        await edit_query_or_reply(
            query,
            report,
            main_keyboard(),
        )
    else:
        await progress.edit_text(
            report,
            parse_mode=ParseMode.HTML,
            reply_markup=main_keyboard(),
        )


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    if not allowed(update):
        await answer_callback(query, "Acesso não autorizado.", show_alert=True)
        return
    await answer_callback(query)
    data = query.data or ""
    if data.startswith("ai_exec_"):
        await execute_ai_pending(update, context, data.removeprefix("ai_exec_"))
        return
    if data.startswith("ai_cancel_"):
        await cancel_ai_pending(update, context, data.removeprefix("ai_cancel_"))
        return
    if data.startswith("pc_cancel_"):
        await cancel_pc_job(update, context, data.removeprefix("pc_cancel_"))
        return
    if data.startswith("pc_job_"):
        await show_pc_job(update, context, data.removeprefix("pc_job_"))
        return
    if data.startswith("svc_restart_confirm_"):
        await show_service_confirm(update, context, "restart", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_start_confirm_"):
        await show_service_confirm(update, context, "start", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_stop_confirm_"):
        await show_service_confirm(update, context, "stop", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_restart_now_"):
        await service_action_now(update, context, "restart", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_start_now_"):
        await service_action_now(update, context, "start", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_stop_now_"):
        await service_action_now(update, context, "stop", data.rsplit("_", 1)[1])
        return
    if data.startswith("svc_") and data != "svc_menu":
        await show_service_detail(update, context, data.removeprefix("svc_"))
        return
    if data.startswith("logs_") and data != "logs_menu":
        await show_logs(update, context, data.removeprefix("logs_"))
        return
    actions = {
        "dashboard": show_dashboard,
        "ops": show_operations,
        "gmail": show_gmail,
        "security": show_security,
        "system": show_system,
        "pc_panel": show_pc_panel,
        "ai_menu": show_ai_menu,
        "pc_jobs": show_pc_jobs,
        "pc_status_request": queue_pc_status,
        "quick_status": show_quick_status,
        "report": show_report,
        "silence_menu": show_silence_menu,
        "silence_30": lambda u, c: set_silence(u, c, 30),
        "silence_60": lambda u, c: set_silence(u, c, 60),
        "silence_180": lambda u, c: set_silence(u, c, 180),
        "silence_off": lambda u, c: set_silence(u, c, 0),
        "maintenance_menu": show_maintenance_menu,
        "maintenance_30": lambda u, c: set_maintenance(u, c, 30),
        "maintenance_60": lambda u, c: set_maintenance(u, c, 60),
        "maintenance_180": lambda u, c: set_maintenance(u, c, 180),
        "maintenance_off": lambda u, c: set_maintenance(u, c, 0),
        "history": show_history,
        "integrity": show_integrity,
        "permissions": show_permissions,
        "updates_menu": show_updates_menu,
        "apt_check": apt_check_now,
        "apt_upgrade_confirm": show_apt_upgrade_confirm,
        "apt_upgrade_now": apt_upgrade_now,
        "svc_menu": show_services,
        "logs_menu": show_logs_menu,
        "network_menu": show_network,
        "scan_confirm": show_scan_confirm,
        "scan_now": scan_now,
        "lock_confirm": show_lock_confirm,
        "lock_now": lock_now,
        "unlock_confirm": show_unlock_confirm,
        "unlock_now": unlock_now,
        "emergency_confirm": show_emergency_confirm,
        "emergency_now": emergency_now,
        "emergency_cleanup_now": lambda u, c: emergency_now(u, c, include_cleanup=True),
        "webcam_confirm": show_webcam_confirm,
        "webcam_now": webcam_now,
        "accounts": show_accounts,
        "stats": show_stats,
        "help": show_help,
        "check": manual_check,
        "shutdown_confirm": show_shutdown_confirm,
        "shutdown_now": shutdown_now,
        "reboot_confirm": show_reboot_confirm,
        "reboot_now": reboot_now,
        "suspend_confirm": show_suspend_confirm,
        "suspend_now": suspend_now,
        "cleanup_confirm": show_cleanup_confirm,
        "cleanup_now": cleanup_now,
    }
    action = actions.get(query.data)
    if action:
        await action(update, context)


async def pc_results_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        jobs = await asyncio.to_thread(pc_bridge.pending_notifications, 10)
    except Exception:
        logger.exception("Falha ao consultar resultados do agente do PC")
        return
    icons = {"completed": "✅", "failed": "❌", "canceled": "🚫"}
    labels = {"completed": "CONCLUÍDA", "failed": "FALHOU", "canceled": "CANCELADA"}
    for job in jobs:
        job_id = str(job.get("job_id", ""))
        status = str(job.get("status", ""))
        action = str(job.get("action", ""))
        result = str(job.get("result_text", ""))[-3000:] or "Sem detalhes adicionais."
        title = PC_ACTION_LABELS.get(action, action)
        elapsed = ""
        if job.get("started_at") and job.get("completed_at"):
            duration = max(0, int(float(job["completed_at"]) - float(job["started_at"])))
            elapsed = f" · {format_age(duration)}"
        message = (
            f"<b>{icons.get(status, '•')} TAREFA {labels.get(status, status.upper())}</b>\n\n"
            f"ID: <code>{html.escape(job_id)}</code>\n"
            f"Ação: <b>{html.escape(title)}</b>{elapsed}\n\n"
            f"<code>{html.escape(result)}</code>"
        )
        artifact_name = str(job.get("artifact_name") or "")
        artifact_path = pc_bridge.ARTIFACT_DIR / artifact_name if artifact_name else None
        try:
            if artifact_path and artifact_path.is_file():
                with artifact_path.open("rb") as artifact:
                    if artifact_path.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}:
                        await context.bot.send_photo(
                            chat_id=get_chat_id(),
                            photo=artifact,
                            caption=f"{icons.get(status, '•')} {title} · tarefa {job_id}",
                        )
                    else:
                        await context.bot.send_document(
                            chat_id=get_chat_id(),
                            document=artifact,
                            caption=f"{icons.get(status, '•')} {title} · tarefa {job_id}",
                        )
            await context.bot.send_message(
                chat_id=get_chat_id(),
                text=message,
                parse_mode=ParseMode.HTML,
                reply_markup=pc_keyboard(),
            )
            await asyncio.to_thread(pc_bridge.mark_notified, job_id)
            await asyncio.to_thread(pc_bridge.delete_artifact, artifact_name or None)
            db.record_action(
                title,
                f"agente:{PC_AGENT_ID}",
                status == "completed",
                f"Tarefa {job_id}: {result[:800]}",
            )
        except Exception:
            logger.exception("Falha ao publicar o resultado da tarefa %s", job_id)


async def check_emails_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    await check_emails(context.bot)


async def battery_watch_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not config_bool("BATTERY_ALERTS_ENABLED", True):
        return
    battery = await asyncio.to_thread(battery_status)
    if not battery:
        return
    now = time.time()
    threshold = config_int("BATTERY_LOW_PERCENT", 25, 1)
    cooldown = config_int("BATTERY_ALERT_INTERVAL_SECONDS", 1800, 60)
    messages = []

    if state.last_power_plugged is None:
        state.last_power_plugged = battery.power_plugged
    elif state.last_power_plugged != battery.power_plugged:
        state.last_power_plugged = battery.power_plugged
        status = "conectado à energia" if battery.power_plugged else "fora da tomada"
        messages.append(f"⚡ Energia alterada: {status}. Bateria {battery.percent:.0f}%.")

    if battery.percent <= threshold and not battery.power_plugged:
        if not state.low_battery_alerted or now - state.last_battery_alert_at >= cooldown:
            messages.append(f"🔋 Bateria baixa: {battery.percent:.0f}% fora da tomada.")
            state.low_battery_alerted = True
            state.last_battery_alert_at = now
    elif battery.percent > threshold + 5 or battery.power_plugged:
        state.low_battery_alerted = False

    for message in messages:
        try:
            await context.bot.send_message(chat_id=get_chat_id(), text=message)
        except Exception:
            logger.exception("Falha ao enviar alerta de bateria")


async def daily_report_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not config_bool("DAILY_REPORT_ENABLED", False):
        return
    now = datetime.now()
    hour = min(config_int("DAILY_REPORT_HOUR", 9, 0), 23)
    minute = min(config_int("DAILY_REPORT_MINUTE", 0, 0), 59)
    today = now.strftime("%Y-%m-%d")
    if state.last_daily_report_date == today:
        return
    if now.hour != hour or now.minute < minute:
        return
    try:
        await context.bot.send_message(
            chat_id=get_chat_id(),
            text=await report_text(),
            parse_mode=ParseMode.HTML,
            reply_markup=main_keyboard(),
        )
        state.last_daily_report_date = today
    except Exception:
        logger.exception("Falha ao enviar relatório diário")


async def smart_alerts_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    if not config_bool("SMART_ALERTS_ENABLED", True):
        return

    now = now_ts()
    cooldown = config_int("SMART_ALERT_COOLDOWN_SECONDS", 1800, 60)
    duration = config_int("SMART_ALERT_DURATION_SECONDS", 180, 30)
    cpu_threshold = config_int("SMART_CPU_PERCENT", 90, 1)
    disk_threshold = config_int("SMART_DISK_PERCENT", 90, 1)
    temp_threshold = config_int("SMART_TEMP_C", 82, 1)

    messages = []
    cpu = await asyncio.to_thread(psutil.cpu_percent, 0.5)
    if cpu >= cpu_threshold:
        state.high_cpu_since = state.high_cpu_since or now
        if now - state.high_cpu_since >= duration:
            messages.append(f"⚠️ CPU alta por {duration}s: {cpu:.1f}%.")
    else:
        state.high_cpu_since = None

    disk = psutil.disk_usage("/")
    if disk.percent >= disk_threshold:
        messages.append(f"⚠️ Disco acima do limite: {disk.percent:.1f}% usado.")

    temp_text = temperature()
    temp_value = parse_temperature_value(temp_text)
    if temp_value is not None and temp_value >= temp_threshold:
        state.high_temp_since = state.high_temp_since or now
        if now - state.high_temp_since >= duration:
            messages.append(f"⚠️ Temperatura alta: {temp_value:.0f}°C.")
    else:
        state.high_temp_since = None

    states = service_states()
    failed = {
        unit
        for unit, value in states.items()
        if value in {"failed", "inactive", "unknown"} and unit != "gmail-telegram-bot.service"
    }
    new_failed = failed - state.known_failed_services
    recovered = state.known_failed_services - failed
    if new_failed:
        labels = ", ".join(SERVICE_BY_UNIT[unit][2] for unit in sorted(new_failed))
        messages.append(f"🚨 Serviço caiu/parou: {labels}.")
    if recovered:
        labels = ", ".join(SERVICE_BY_UNIT[unit][2] for unit in sorted(recovered))
        messages.append(f"✅ Serviço recuperado: {labels}.")
    state.known_failed_services = failed

    if not messages:
        return
    if now - state.last_resource_alert_at < cooldown:
        return
    state.last_resource_alert_at = now
    try:
        await send_proactive_message(
            context.bot,
            "\n".join(messages),
        )
    except Exception:
        logger.exception("Falha ao enviar alerta inteligente")


async def post_init(application: Application) -> None:
    await application.bot.set_my_commands(
        [
            BotCommand("painel", "Abrir central Kali Bunker"),
            BotCommand("seguranca", "Ver estado das defesas"),
            BotCommand("sistema", "Ver saúde do computador"),
            BotCommand("pc", "Abrir o agente e a fila do meu PC"),
            BotCommand("tarefas", "Ver tarefas enviadas ao PC"),
            BotCommand("cancelar", "Cancelar uma tarefa pelo ID"),
            BotCommand("resumo", "Status rápido do sistema"),
            BotCommand("relatorio", "Gerar relatório completo"),
            BotCommand("servicos", "Controlar módulos do Kali Bunker"),
            BotCommand("servico", "Controlar módulo por argumento"),
            BotCommand("logs", "Ver logs de um módulo"),
            BotCommand("scan", "Escanear a rede local"),
            BotCommand("bloquear", "Bloquear a tela"),
            BotCommand("desbloquear", "Desbloquear a tela"),
            BotCommand("emergencia", "Modo emergência"),
            BotCommand("silenciar", "Silenciar alertas"),
            BotCommand("manutencao", "Modo manutenção"),
            BotCommand("integridade", "Checar integridade"),
            BotCommand("permissoes", "Checar permissões"),
            BotCommand("historico", "Ver ações remotas"),
            BotCommand("atualizar", "Atualizações do sistema"),
            BotCommand("webcam", "Capturar foto da webcam"),
            BotCommand("ia", "Conversar com a IA do Kali Bunker"),
            BotCommand("gmail", "Abrir monitor Gmail"),
            BotCommand("contas", "Listar contas monitoradas"),
            BotCommand("verificar", "Verificar novos e-mails agora"),
            BotCommand("desligar", "Confirmar desligamento do PC"),
            BotCommand("reiniciar", "Confirmar reinicialização do PC"),
            BotCommand("suspender", "Confirmar suspensão do PC"),
            BotCommand("limpeza", "Confirmar limpeza do sistema"),
            BotCommand("ajuda", "Ajuda da central Kali Bunker"),
        ]
    )
    try:
        await application.bot.send_message(
            chat_id=get_chat_id(),
            text=(
                "<b>🛡️ Kali Security Bunker online</b>\n"
                f"{len(SECURITY_SERVICES)} módulos monitorados · "
                f"{len(gmail_services)} contas Gmail\n\n"
                f"<code>{html.escape(startup_context()[-800:])}</code>"
            ),
            parse_mode=ParseMode.HTML,
            reply_markup=main_keyboard(),
        )
    except Exception:
        logger.exception("Não foi possível enviar mensagem inicial do bot")


async def handle_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Erro ao processar atualização do Telegram", exc_info=context.error)


def start_bot() -> None:
    db.init_db()
    pc_bridge.init_db()
    validate_config()
    init_gmail_services()

    request = HTTPXRequest(
        connect_timeout=10,
        read_timeout=25,
        write_timeout=20,
        pool_timeout=10,
    )
    application = (
        Application.builder()
        .token(config.TELEGRAM_TOKEN)
        .request(request)
        .get_updates_request(request)
        .post_init(post_init)
        .build()
    )

    application.add_handler(CommandHandler(["start", "painel", "statusbot"], show_dashboard))
    application.add_handler(CommandHandler("seguranca", show_security))
    application.add_handler(CommandHandler("sistema", show_system))
    application.add_handler(CommandHandler("pc", show_pc_panel))
    application.add_handler(CommandHandler("tarefas", show_pc_jobs))
    application.add_handler(CommandHandler("cancelar", manual_cancel_pc_job))
    application.add_handler(CommandHandler("resumo", show_quick_status))
    application.add_handler(CommandHandler("relatorio", show_report))
    application.add_handler(CommandHandler("servicos", show_services))
    application.add_handler(CommandHandler("servico", manual_service))
    application.add_handler(CommandHandler("logs", manual_logs))
    application.add_handler(CommandHandler("scan", manual_scan))
    application.add_handler(CommandHandler("bloquear", show_lock_confirm))
    application.add_handler(CommandHandler("desbloquear", show_unlock_confirm))
    application.add_handler(CommandHandler("emergencia", show_emergency_confirm))
    application.add_handler(CommandHandler("silenciar", show_silence_menu))
    application.add_handler(CommandHandler("manutencao", show_maintenance_menu))
    application.add_handler(CommandHandler("integridade", show_integrity))
    application.add_handler(CommandHandler("permissoes", show_permissions))
    application.add_handler(CommandHandler("historico", show_history))
    application.add_handler(CommandHandler("atualizar", show_updates_menu))
    application.add_handler(CommandHandler("webcam", show_webcam_confirm))
    application.add_handler(CommandHandler("ia", ai_command))
    application.add_handler(CommandHandler(["gmail", "status"], show_gmail))
    application.add_handler(CommandHandler("contas", show_accounts))
    application.add_handler(CommandHandler("verificar", manual_check))
    application.add_handler(CommandHandler("desligar", show_shutdown_confirm))
    application.add_handler(CommandHandler("reiniciar", show_reboot_confirm))
    application.add_handler(CommandHandler("suspender", show_suspend_confirm))
    application.add_handler(CommandHandler("limpeza", show_cleanup_confirm))
    application.add_handler(CommandHandler("ajuda", show_help))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, ai_text_message))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_error_handler(handle_error)

    application.job_queue.run_repeating(
        check_emails_job,
        interval=config.CHECK_INTERVAL_SECONDS,
        first=5,
        name="gmail-monitor",
    )
    application.job_queue.run_repeating(
        battery_watch_job,
        interval=120,
        first=15,
        name="battery-watch",
    )
    application.job_queue.run_repeating(
        daily_report_job,
        interval=300,
        first=30,
        name="daily-report",
    )
    application.job_queue.run_repeating(
        smart_alerts_job,
        interval=60,
        first=45,
        name="smart-alerts",
    )
    application.job_queue.run_repeating(
        pc_results_job,
        interval=3,
        first=3,
        name="pc-results",
    )

    backoff = 5
    while True:
        try:
            application.run_polling(
                close_loop=False,
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=False,
            )
            return
        except Conflict:
            logger.warning("Outra instância está usando o bot; nova tentativa em %ss", backoff)
            time.sleep(backoff)
            backoff = min(300, backoff * 2)
        except Exception:
            logger.exception("Falha fatal no polling do Telegram")
            return
