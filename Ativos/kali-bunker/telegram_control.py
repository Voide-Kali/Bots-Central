#!/usr/bin/env python3
"""Controle do Kali Bunker por comandos do Telegram."""

from __future__ import annotations

import importlib.util
import secrets
import time
from contextvars import ContextVar
from pathlib import Path
import os
from typing import Any

import requests

import voice_vault
from action_policy import PolicyViolation
from bunker_audit import STATE_DIR, record_event
from bunker_config import (
    TELEGRAM_ALLOWED_CHAT_IDS,
    TELEGRAM_ALLOWED_USER_IDS,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    TELEGRAM_POLL_INTERVAL_SECONDS,
)
from bunkerctl import (
    add_ban_record,
    annotate_devices,
    apply_ban_rules,
    default_scan_target,
    normalize_ip,
    normalize_mac,
    scan_network_devices,
)
from remote_control import (
    RemoteFeatureDisabled,
    ai_assistant,
    archive_for_send,
    cancel_pending,
    cleanup_export_artifact,
    clear_ai_chat_history,
    create_pending,
    execute_shell,
    execute_typed_action,
    install_package,
    list_pending,
    pop_pending,
    remote_action_disabled_message,
    remote_action_enabled,
    validate_pending_item,
)
from state_utils import claim_monotonic_json_counter, read_json_counter


API_TIMEOUT = 35
TELEGRAM_OFFSET_FILE = STATE_DIR / "telegram-control-offset.json"
TELEGRAM_OFFSET_KEY = "next_update_id"
VAULT_SESSION_SECONDS = 5 * 60
VAULT_INPUT_SECONDS = 2 * 60
SERVICE_UNITS_BY_CODE = {
    "BT": "bt-alarm.service",
    "AUTH": "monitor-auth.service",
    "SYS": "monitor-recursos.service",
    "WIFI": "monitor-wifi.service",
    "FILE": "monitor-arquivos.service",
    "USB": "usbguard.service",
    "BAN": "fail2ban.service",
}
_VAULT_SESSIONS: dict[str, dict[str, Any]] = {}
_VAULT_INPUTS: dict[str, dict[str, Any]] = {}
_VAULT_CONFIRMATIONS: dict[str, dict[str, Any]] = {}
_AUTHORIZED_USER_ID: ContextVar[str | None] = ContextVar("telegram_authorized_user_id", default=None)


def inline_button(text: str, callback_data: str) -> dict[str, str]:
    return {"text": text, "callback_data": callback_data}


def main_keyboard() -> dict[str, Any]:
    # Compatibilidade: permite ativar o "painel antigo" via VAR AMBIENTE
    # export KALI_BUNKER_OLD_PANEL=1
    if os.environ.get("KALI_BUNKER_OLD_PANEL", "").lower() in {"1", "true", "yes"}:
        # Painel antigo: teclado tipo ReplyKeyboard com botões maiores em linhas
        return {
            "inline_keyboard": [
                [inline_button("Painel", "menu:status"), inline_button("IA", "menu:ia")],
                [inline_button("Serviços", "menu:services"), inline_button("Rede", "menu:rede")],
                [inline_button("Cofre", "vault:menu"), inline_button("Pendentes", "menu:pendentes")],
                [inline_button("Terminal", "menu:terminal"), inline_button("Arquivo", "menu:arquivo")],
            ],
            "keyboard": [
                [
                    {"text": "Painel"},
                    {"text": "IA"},
                    {"text": "Serviços"},
                    {"text": "Rede"},
                ],
                [
                    {"text": "Cofre"},
                    {"text": "Pendentes"},
                    {"text": "Terminal"},
                    {"text": "Arquivo"},
                ],
            ],
            "resize_keyboard": True,
            "one_time_keyboard": False,
        }

    return {
        "inline_keyboard": [
            [inline_button("Painel", "menu:status"), inline_button("IA", "menu:ia")],
            [inline_button("Serviços", "menu:services"), inline_button("Rede", "menu:rede")],
            [inline_button("Cofre", "vault:menu"), inline_button("Pendentes", "menu:pendentes")],
            [inline_button("Terminal", "menu:terminal"), inline_button("Arquivo", "menu:arquivo")],
        ]
    }


def status_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Atualizar", "menu:status"), inline_button("Serviços", "menu:services")],
            [inline_button("Rede", "menu:rede"), inline_button("Pendentes", "menu:pendentes")],
            [inline_button("Voltar", "menu:home")],
        ]
    }


def services_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Ligar tudo", "svc:up"), inline_button("Reiniciar tudo", "svc:restart")],
            [inline_button("Desligar tudo", "svc:down"), inline_button("Status", "menu:status")],
            [inline_button("Voltar", "menu:home")],
        ]
    }


def network_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Scan atual", "net:scan"), inline_button("Bloqueios", "net:bans")],
            [inline_button("Painel", "menu:status"), inline_button("Voltar", "menu:home")],
        ]
    }


def terminal_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Status", "term:status"), inline_button("Pendentes", "menu:pendentes")],
            [inline_button("Ajuda", "term:help"), inline_button("Voltar", "menu:home")],
        ]
    }


def file_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Enviar Downloads", "file:downloads"), inline_button("Enviar Documentos", "file:documents")],
            [inline_button("Ajuda", "file:help"), inline_button("Voltar", "menu:home")],
        ]
    }


def ai_keyboard() -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [inline_button("Perguntar", "ai:ask"), inline_button("Estudar", "ai:study")],
            [inline_button("Diagnosticar", "ai:diagnose"), inline_button("Memória", "ai:memory")],
            [inline_button("Limpar conversa", "ai:clear"), inline_button("Voltar", "menu:home")],
        ]
    }


def confirmation_keyboard(code: str) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [
                inline_button("Confirmar", f"confirm:{code}"),
                inline_button("Cancelar", f"cancel:{code}"),
            ]
        ]
    }


def redact_token(text: str) -> str:
    if not TELEGRAM_BOT_TOKEN:
        return text
    return text.replace(TELEGRAM_BOT_TOKEN, "<token>")


def allowed_chat_ids() -> set[str]:
    configured = TELEGRAM_ALLOWED_CHAT_IDS or TELEGRAM_CHAT_ID
    return {item.strip() for item in configured.split(",") if item.strip()}


def allowed_user_ids() -> set[str]:
    configured = TELEGRAM_ALLOWED_USER_IDS or TELEGRAM_CHAT_ID
    return {item.strip() for item in configured.split(",") if item.strip()}


def is_allowed_chat(chat_id: object) -> bool:
    return str(chat_id) in allowed_chat_ids()


def is_allowed_user(user_id: object) -> bool:
    return str(user_id) in allowed_user_ids()


def is_authorized_sender(chat_id: object, user_id: object) -> bool:
    return is_allowed_chat(chat_id) and is_allowed_user(user_id)


def require_remote_action(chat_id: str, action: str, callback_id: str | None = None) -> bool:
    if remote_action_enabled(action):
        return True
    message = remote_action_disabled_message(action)
    if callback_id:
        answer_callback(callback_id, "Recurso desabilitado.")
    send_message(chat_id, message)
    return False


def api_url(method: str) -> str:
    return f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}"


def telegram_request(method: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    try:
        response = requests.post(api_url(method), json=payload, timeout=API_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code == 409 and method == "getUpdates":
            print("[telegram-control] conflito em getUpdates: outro processo esta usando o mesmo bot do Telegram.")
        else:
            print(f"[telegram-control] erro em {method}: {redact_token(str(exc))}")
        return None
    except requests.RequestException as exc:
        print(f"[telegram-control] erro em {method}: {redact_token(str(exc))}")
        return None
    if not data.get("ok"):
        print(f"[telegram-control] resposta invalida em {method}: {data}")
        return None
    return data


def send_message(
    chat_id: str,
    text: str,
    reply_markup: dict[str, Any] | None = None,
    protect_content: bool = False,
) -> None:
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text[:4000],
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    if protect_content:
        payload["protect_content"] = True
    telegram_request("sendMessage", payload)


def delete_message(chat_id: str, message_id: object) -> None:
    if message_id in {None, ""}:
        return
    telegram_request("deleteMessage", {"chat_id": chat_id, "message_id": message_id})


def send_document(chat_id: str, path: str, caption: str) -> bool:
    try:
        with open(path, "rb") as document:
            response = requests.post(
                api_url("sendDocument"),
                data={"chat_id": chat_id, "caption": caption[:1024]},
                files={"document": document},
                timeout=API_TIMEOUT,
            )
        response.raise_for_status()
        data = response.json()
    except (OSError, requests.RequestException) as exc:
        print(f"[telegram-control] erro em sendDocument: {redact_token(str(exc))}")
        return False
    return bool(data.get("ok"))


def capture_webcam_photo() -> tuple[str | None, str]:
    if not remote_action_enabled("webcam"):
        return None, remote_action_disabled_message("webcam")
    module_path = Path(__file__).with_name("monitor-auth.py")
    if not module_path.exists():
        return None, "Modulo da camera nao encontrado."
    try:
        spec = importlib.util.spec_from_file_location("monitor_auth_runtime", module_path)
        if not spec or not spec.loader:
            return None, "Nao consegui carregar o modulo da camera."
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        photo = module.tirar_foto()
    except Exception as exc:
        return None, f"Falha ao capturar webcam: {exc}"
    if not photo:
        return None, "Webcam nao gerou imagem. Verifique camera, /dev/video0 e fswebcam."
    return str(photo), "Foto da webcam capturada."


def answer_callback(callback_id: str, text: str) -> None:
    telegram_request("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190]})


def get_updates(offset: int | None) -> list[dict[str, Any]] | None:
    payload: dict[str, Any] = {
        "timeout": 30,
        "allowed_updates": ["message", "callback_query"],
    }
    if offset is not None:
        payload["offset"] = offset
    data = telegram_request("getUpdates", payload)
    if data is None:
        return None
    result = data.get("result")
    return result if isinstance(result, list) else []


def load_telegram_offset() -> int | None:
    offset = read_json_counter(TELEGRAM_OFFSET_FILE, TELEGRAM_OFFSET_KEY)
    if offset is None and TELEGRAM_OFFSET_FILE.exists():
        raise RuntimeError("estado de offset do Telegram corrompido ou inseguro; replay recusado")
    return offset


def claim_update_before_processing(update: dict[str, Any]) -> tuple[bool, int | None]:
    """Reivindica o update em disco antes de qualquer efeito (semantica at-most-once)."""
    update_id = update.get("update_id")
    if not isinstance(update_id, int) or isinstance(update_id, bool) or update_id < 0:
        record_event("telegram_update_rejected", reason="invalid_update_id")
        return False, load_telegram_offset()
    accepted, next_offset = claim_monotonic_json_counter(
        TELEGRAM_OFFSET_FILE,
        TELEGRAM_OFFSET_KEY,
        update_id + 1,
    )
    if not accepted:
        record_event("telegram_update_replay_rejected", update_id=update_id, next_offset=next_offset)
    return accepted, next_offset


def process_update_at_most_once(update: dict[str, Any]) -> int | None:
    """Persiste a reivindicacao e so depois despacha o efeito do update."""
    accepted, next_offset = claim_update_before_processing(update)
    if not accepted:
        return next_offset
    if "message" in update:
        handle_message(update["message"])
    elif "callback_query" in update:
        handle_callback(update["callback_query"])
    return next_offset


def polling_retry_delay(consecutive_failures: int) -> int:
    """Return a bounded exponential delay after a failed Telegram request."""
    base = max(1, TELEGRAM_POLL_INTERVAL_SECONDS)
    exponent = max(0, min(consecutive_failures - 1, 6))
    return min(60, base * (2**exponent))


def command_help() -> str:
    return (
        "Kali Bunker - Central de Controle\n\n"
        "Use os botões para operar por área. Ações que executam comando, enviam arquivo, instalam pacote "
        "ou mexem em serviço sempre criam confirmação antes de rodar.\n\n"
        "/rede - escaneia a rede atual do PC\n"
        "/rede 192.168.3.0/24 - escaneia uma rede especifica\n"
        "/banip 192.168.3.50 - bloqueia IP no Kali Bunker\n"
        "/banmac AA:BB:CC:DD:EE:FF - bloqueia MAC no Kali Bunker\n"
        "/banidos - lista bloqueios registrados\n\n"
        "/status - mostra saúde resumida do PC\n"
        "/cmd COMANDO - prepara comando de terminal\n"
        "/arquivo CAMINHO - prepara envio de arquivo/pasta\n"
        "/ia PERGUNTA - conversa com a IA\n"
        "/estudar TEMA - monta um plano de estudo\n"
        "/explicar TEMA - explica como professor\n"
        "/resumir TEXTO/TEMA - cria resumo de estudo\n"
        "/quiz TEMA - cria perguntas para treinar\n"
        "/limparia - apaga a memória curta da IA neste chat\n"
        "/senhas - abre o cofre local de senhas\n"
        "/pendentes - lista ações aguardando confirmação\n"
        "/confirmar CODIGO - executa ação pendente\n"
        "/cancelar CODIGO - cancela ação pendente\n\n"
        "O bot aceita comandos apenas do chat autorizado no .env."
    )


def ai_menu_text() -> str:
    return (
        "IA pronta - Kali Bunker\n\n"
        "Fale normalmente ou escolha uma intenção abaixo. "
        "A IA ajuda com estudo, Linux, logs, erros, organização, segurança defensiva e ações do PC com confirmação."
    )


def services_menu_text() -> str:
    return (
        "Serviços do Kali Bunker\n\n"
        "Controle os módulos principais em lote. Ligar/reiniciar/desligar cria ação pendente para confirmação."
    )


def network_menu_text() -> str:
    return (
        "Rede\n\n"
        "Use Scan atual para listar dispositivos da rede conectada. "
        "Dispositivos desconhecidos aparecem com botões para bloqueio local."
    )


def terminal_menu_text() -> str:
    return (
        "Terminal\n\n"
        "Envie /cmd COMANDO para criar uma ação pendente. "
        "Nada executa sem confirmar pelo botão ou por /confirmar CODIGO."
    )


def file_menu_text() -> str:
    return (
        "Arquivos\n\n"
        "Envie /arquivo CAMINHO para preparar envio de arquivo ou pasta. "
        "Pastas são compactadas antes do envio."
    )


def format_devices(devices: list[dict[str, str]], target: str) -> str:
    lines = [f"Rede escaneada: {target}", ""]
    if not devices:
        lines.append("Nenhum dispositivo encontrado.")
        return "\n".join(lines)
    for index, device in enumerate(devices, start=1):
        status = "banido" if device.get("banned") == "yes" else "conhecido" if device.get("known") == "yes" else "desconhecido"
        lines.append(
            f"{index}. {device.get('ip', '-')}"
            f"\n   MAC: {device.get('mac') or 'N/D'}"
            f"\n   Host: {device.get('hostname') or 'N/D'}"
            f"\n   Fabricante: {device.get('vendor') or 'N/D'}"
            f"\n   Status: {status}"
        )
    return "\n".join(lines)


def device_keyboard(devices: list[dict[str, str]]) -> dict[str, Any] | None:
    rows = []
    for device in devices[:8]:
        ip = device.get("ip", "")
        mac = device.get("mac", "")
        if device.get("known") == "yes" or device.get("banned") == "yes":
            continue
        if ip:
            rows.append([{"text": f"Banir IP {ip}", "callback_data": f"ban_ip:{ip}"}])
        if mac:
            rows.append([{"text": f"Banir MAC {mac}", "callback_data": f"ban_mac:{mac}"}])
    return {"inline_keyboard": rows} if rows else None


def handle_rede(chat_id: str, text: str) -> None:
    parts = text.split(maxsplit=1)
    try:
        target = parts[1].strip() if len(parts) > 1 else default_scan_target()
        devices = annotate_devices(scan_network_devices(target))
    except Exception as exc:
        send_message(chat_id, f"Falha no scan: {exc}")
        record_event("telegram_network_scan", success=False, error=str(exc))
        return

    send_message(chat_id, format_devices(devices, target), device_keyboard(devices))
    record_event("telegram_network_scan", success=True, target=target, devices=len(devices))


def apply_telegram_ban(kind: str, value: str, reason: str = "bloqueio via Telegram") -> tuple[bool, str]:
    try:
        normalized = normalize_ip(value) if kind == "ip" else normalize_mac(value)
        add_ban_record(kind, normalized, reason)
        failures, messages = apply_ban_rules(kind, normalized)
    except Exception as exc:
        return False, f"Falha ao bloquear {kind} {value}: {exc}"

    detail = "\n".join(f"- {message}" for message in messages[:6])
    status = "Bloqueio aplicado" if failures == 0 else f"Bloqueio registrado com {failures} falha(s)"
    record_event("telegram_network_ban", type=kind, value=normalized, failures=failures)
    return failures == 0, f"{status}: {kind} {normalized}\n{detail}".strip()


def list_bans_text() -> str:
    from bunkerctl import load_banlist

    bans = load_banlist()
    if not bans:
        return "Nenhum dispositivo banido."
    lines = ["Dispositivos banidos:"]
    for item in bans[-12:]:
        lines.append(
            f"- {str(item.get('type', '-')).upper()} {item.get('value', '-')}"
            f" | {item.get('reason', '-')}"
        )
    return "\n".join(lines)


def status_text() -> str:
    from bunker_health import collect_health

    health = collect_health()
    resources = health["resources"]
    services = health.get("services", [])
    active = sum(1 for item in services if item.get("state") == "active")
    failed_items = health.get("critical_failed", [])
    failed = ", ".join(failed_items) if failed_items else "nenhuma"
    return (
        f"Painel Kali Bunker\n\n"
        f"Host: {health['host']}\n"
        f"Estado: {'OK' if health['healthy'] else 'ATENÇÃO'}\n"
        f"Serviços ativos: {active}/{len(services)}\n"
        f"CPU: {resources['cpu_percent']:.1f}%\n"
        f"RAM: {resources['memory_percent']:.1f}%\n"
        f"Disco: {resources['disk_percent']:.1f}% ({resources['disk_free_gib']} GiB livres)\n"
        f"Temperatura: {resources.get('temperature_c') or 'N/D'}°C\n"
        f"Pendências críticas: {failed}"
    )


def _effective_pending_user_id(user_id: str | None = None) -> str | None:
    return str(user_id) if user_id is not None and str(user_id).strip() else _AUTHORIZED_USER_ID.get()


def pending_text(chat_id: str, user_id: str | None = None) -> str:
    bound_user_id = _effective_pending_user_id(user_id)
    items = list_pending(chat_id, user_id=bound_user_id)
    if not items:
        return "Nenhuma ação pendente."
    lines = ["Ações pendentes:"]
    for code, item in items[-10:]:
        lines.append(f"- {code}: {item.get('description', item.get('action', '-'))}")
    return "\n".join(lines)


def request_confirmation(
    chat_id: str,
    action: str,
    payload: dict[str, Any],
    description: str,
    user_id: str | None = None,
) -> None:
    try:
        code = create_pending(
            chat_id,
            action,
            payload,
            description,
            user_id=_effective_pending_user_id(user_id),
        )
    except (RemoteFeatureDisabled, PolicyViolation) as exc:
        send_message(chat_id, str(exc))
        return
    send_message(
        chat_id,
        f"Ação pendente: {description}\n\nCódigo: {code}\nExecute com: /confirmar {code}\nCancele com: /cancelar {code}",
        confirmation_keyboard(code),
    )


def handle_cmd(chat_id: str, text: str, user_id: str | None = None) -> None:
    command = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
    if not command:
        send_message(chat_id, "Uso: /cmd COMANDO")
        return
    request_confirmation(chat_id, "shell", {"command": command}, f"Executar no terminal: {command}", user_id)


def handle_file_request(chat_id: str, raw_path: str, user_id: str | None = None) -> None:
    path = raw_path.strip()
    if not path:
        send_message(chat_id, "Uso: /arquivo CAMINHO")
        return
    request_confirmation(chat_id, "send_path", {"path": path}, f"Enviar arquivo/pasta: {path}", user_id)


def handle_ai(chat_id: str, text: str, user_id: str | None = None) -> None:
    prompt = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
    if not prompt:
        send_message(chat_id, "Uso: /ia PERGUNTA")
        return
    try:
        plan = ai_assistant(prompt, chat_id)
    except Exception as exc:
        send_message(chat_id, f"Falha na IA: {exc}")
        record_event("telegram_ai_chat", success=False, error=str(exc))
        return

    action = plan.get("action", "")
    explanation = plan.get("explanation", "ação solicitada")
    if action == "chat":
        response = plan.get("response") or "Não consegui montar uma resposta."
        send_message(chat_id, response)
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "status":
        send_message(chat_id, status_text())
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "shell" and plan.get("command"):
        request_confirmation(
            chat_id,
            "shell",
            {"command": plan["command"]},
            f"IA: {explanation}\nComando: {plan['command']}",
            user_id,
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "send_path" and plan.get("path"):
        request_confirmation(
            chat_id,
            "send_path",
            {"path": plan["path"]},
            f"IA: {explanation}\nCaminho: {plan['path']}",
            user_id,
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "install_package" and plan.get("package"):
        request_confirmation(
            chat_id,
            "install_package",
            {"package": plan["package"]},
            f"IA: {explanation}\nPacote: {plan['package']}",
            user_id,
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "service" and plan.get("service_action") and plan.get("service_code"):
        service_action = str(plan["service_action"])
        service_code = str(plan["service_code"]).upper()
        if service_action not in {"start", "stop", "restart"} or service_code not in SERVICE_UNITS_BY_CODE:
            send_message(chat_id, "Serviço não reconhecido para execução por este controlador.")
            return
        request_confirmation(
            chat_id,
            "service",
            {"service_action": service_action, "service_code": service_code},
            f"IA: {explanation}\nServiço: {service_code}\nAção: {service_action}",
            user_id,
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "webcam":
        request_confirmation(
            chat_id,
            "webcam",
            {},
            f"IA: {explanation}\nCapturar e enviar foto da webcam.",
            user_id,
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    if action == "purge_bot_messages":
        send_message(
            chat_id,
            "Nao consigo apagar o historico inteiro do Telegram sem IDs guardados. "
            "Use /limparia para limpar a memoria curta da IA neste chat.",
        )
        record_event("telegram_ai_chat", success=True, action=action)
        return
    send_message(chat_id, "IA gerou uma ação incompleta.")


def handle_study(chat_id: str, text: str, mode: str) -> None:
    prompts = {
        "estudar": (
            "Monte um plano de estudo prático para este tema. "
            "Inclua ordem dos tópicos, tempo sugerido, exercícios, revisão e uma primeira tarefa: {content}"
        ),
        "explicar": (
            "Explique este tema como professor particular. Use linguagem simples, exemplos e uma sequência passo a passo: "
            "{content}"
        ),
        "resumir": (
            "Faça um resumo de estudo claro e organizado. Destaque conceitos-chave, pontos que costumam cair em prova "
            "e perguntas de revisão: {content}"
        ),
        "quiz": (
            "Crie um quiz de estudo sobre este tema. Faça perguntas de níveis fácil, médio e difícil, com gabarito "
            "e explicação curta no final: {content}"
        ),
    }
    command = text.split(maxsplit=1)[0]
    content = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
    if not content:
        send_message(chat_id, f"Uso: {command} TEMA")
        return
    handle_ai(chat_id, f"/ia {prompts[mode].format(content=content)}")


def execute_pending_action(chat_id: str, code: str, user_id: str | None = None) -> None:
    bound_user_id = _effective_pending_user_id(user_id)
    item = pop_pending(chat_id, code, user_id=bound_user_id)
    if not item:
        send_message(chat_id, "Código pendente não encontrado para este chat.")
        return

    try:
        action, payload = validate_pending_item(item)
    except PolicyViolation as exc:
        record_event("telegram_pending_revalidation_failed", chat_id=chat_id, user_id=bound_user_id, error=str(exc))
        send_message(chat_id, "Ação recusada: a confirmação não passou na revalidação de segurança.")
        return
    if not remote_action_enabled(str(action)):
        send_message(chat_id, remote_action_disabled_message(str(action)))
        return
    if action == "shell":
        command = str(payload.get("command", ""))
        status, output = execute_shell(command)
        send_message(chat_id, f"Comando finalizado com código {status}:\n\n{output}")
        return
    if action in {"service", "bunker_services"}:
        try:
            status, output = execute_typed_action(action, payload)
        except PolicyViolation as exc:
            send_message(chat_id, f"Ação tipada recusada: {exc}")
            return
        send_message(chat_id, f"Ação finalizada com código {status}:\n\n{output}")
        return
    if action == "send_path":
        target, message = archive_for_send(str(payload.get("path", "")))
        if not target:
            send_message(chat_id, message)
            return
        try:
            sent = send_document(chat_id, str(target), message)
        finally:
            cleanup_export_artifact(Path(target))
        send_message(chat_id, "Arquivo enviado." if sent else f"Falha ao enviar. {message}")
        return
    if action == "webcam":
        photo, message = capture_webcam_photo()
        if not photo:
            send_message(chat_id, message)
            return
        sent = send_document(chat_id, photo, message)
        Path(photo).unlink(missing_ok=True)
        send_message(chat_id, "Foto enviada." if sent else "Falha ao enviar a foto da webcam.")
        return
    if action == "install_package":
        ok, detail = install_package(str(payload.get("package", "")))
        send_message(chat_id, f"Pacote instalado.\n\n{detail}" if ok else f"Falha ao instalar pacote:\n\n{detail}")
        return
    if action == "vault_reveal":
        handle_vault_reveal_confirmation(chat_id, item)
        return
    if action == "vault_delete":
        handle_vault_delete_confirmation(chat_id, item)
        return
    send_message(chat_id, f"Ação desconhecida: {action}")


def handle_confirm(chat_id: str, text: str, user_id: str | None = None) -> None:
    code = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
    execute_pending_action(chat_id, code, user_id)


def handle_cancel(chat_id: str, text: str, user_id: str | None = None) -> None:
    code = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""
    if not code:
        send_message(chat_id, "Uso: /cancelar CODIGO")
        return
    send_message(
        chat_id,
        "Ação cancelada."
        if cancel_pending(chat_id, code, user_id=_effective_pending_user_id(user_id))
        else "Código não encontrado.",
    )


def handle_ai_clear(chat_id: str) -> None:
    clear_ai_chat_history(chat_id)
    send_message(chat_id, "Memória curta da IA apagada neste chat.", ai_keyboard())


def handle_ai_callback(chat_id: str, callback_id: str, data: str) -> None:
    action = data.split(":", 1)[1] if ":" in data else "menu"
    prompts = {
        "ask": "Estou pronto. Me pergunte qualquer coisa ou diga a tarefa crua que eu organizo.",
        "study": "Quero estudar. Me pergunte o tema e depois ofereça plano, resumo ou quiz.",
        "diagnose": "Me ajude a diagnosticar. Pergunte se é erro, serviço, log, rede, jogo travando ou função do Kali Bunker.",
        "memory": "o que voce lembra?",
    }
    if action == "menu":
        answer_callback(callback_id, "IA.")
        send_message(chat_id, ai_menu_text(), ai_keyboard())
        return
    if action == "clear":
        answer_callback(callback_id, "Conversa limpa.")
        handle_ai_clear(chat_id)
        return
    prompt = prompts.get(action)
    if not prompt:
        answer_callback(callback_id, "Comando desconhecido.")
        return
    answer_callback(callback_id, "IA.")
    handle_ai(chat_id, f"/ia {prompt}")


def vault_keyboard(unlocked: bool) -> dict[str, Any]:
    if unlocked:
        rows = [
            [inline_button("Listar", "vault:list"), inline_button("Buscar", "vault:find")],
            [inline_button("Gerar e salvar", "vault:generate"), inline_button("Gerar avulsa", "vault:quickgen")],
            [inline_button("Adicionar", "vault:add"), inline_button("Apagar", "vault:delete")],
            [inline_button("Trocar mestra", "vault:change_master"), inline_button("Bloquear", "vault:lock")],
            [inline_button("Voltar", "menu:home")],
        ]
    else:
        rows = [
            [inline_button("Desbloquear", "vault:unlock"), inline_button("Gerar avulsa", "vault:quickgen")],
            [inline_button("Ajuda", "vault:help"), inline_button("Voltar", "menu:home")],
        ]
    return {"inline_keyboard": rows}


def vault_help_text() -> str:
    return (
        "Cofre de senhas local\n\n"
        "Comandos rápidos:\n"
        "/senhas - abre o menu\n"
        "/senhas desbloquear SENHA_MESTRA - use só se precisar; o botão é mais seguro\n"
        "/senhas listar\n"
        "/senhas buscar NOME_OU_TRECHO - cria confirmação antes de revelar\n"
        "/senhas gerar - gera senha avulsa\n"
        "/senhas gerar NOME | USUARIO | URL | TAMANHO - salva e cria confirmação para revelar\n"
        "/senhas salvar NOME | USUARIO | SENHA | URL | NOTAS\n"
        "/senhas apagar NOME_EXATO - cria confirmação antes de apagar\n"
        "/senhas trocar NOVA_SENHA_MESTRA\n"
        "/senhas bloquear\n\n"
        "O cofre fica criptografado no PC. A senha mestra fica só em memória por 5 minutos, "
        "revelação de senha exige confirmação e mensagens sensíveis são apagadas quando o Telegram permite."
    )


def _vault_session_master(chat_id: str, refresh: bool = True) -> str | None:
    session = _VAULT_SESSIONS.get(chat_id)
    if not session:
        return None
    if float(session.get("expires_at", 0)) <= time.time():
        _VAULT_SESSIONS.pop(chat_id, None)
        return None
    if refresh:
        session["expires_at"] = time.time() + VAULT_SESSION_SECONDS
    master_password = str(session.get("master_password", ""))
    return master_password or None


def _vault_set_session(chat_id: str, master_password: str) -> None:
    _VAULT_SESSIONS[chat_id] = {
        "master_password": master_password,
        "expires_at": time.time() + VAULT_SESSION_SECONDS,
    }


def _vault_lock(chat_id: str) -> None:
    _VAULT_SESSIONS.pop(chat_id, None)
    _VAULT_INPUTS.pop(chat_id, None)
    for ref, item in list(_VAULT_CONFIRMATIONS.items()):
        if str(item.get("chat_id")) == str(chat_id):
            _VAULT_CONFIRMATIONS.pop(ref, None)


def _vault_require_master(chat_id: str) -> str | None:
    master_password = _vault_session_master(chat_id)
    if master_password:
        return master_password
    send_message(
        chat_id,
        "Cofre bloqueado. Toque em Desbloquear ou use /senhas desbloquear SENHA_MESTRA.",
        vault_keyboard(False),
    )
    return None


def vault_menu_text(chat_id: str) -> str:
    unlocked = _vault_session_master(chat_id, refresh=False) is not None
    status = "desbloqueado" if unlocked else "bloqueado"
    file_status = "criado" if voice_vault.vault_exists() else "ainda não criado"
    return (
        "Cofre de senhas\n\n"
        f"Status: {status}\n"
        f"Arquivo: {file_status}\n\n"
        "Use os botões para operar ou envie /senhas ajuda para ver comandos rápidos."
    )


def _vault_input_prompt(action: str) -> str:
    prompts = {
        "unlock": "Envie somente a senha mestra do cofre. A mensagem será apagada quando possível.",
        "add": "Envie: Nome | usuário | senha | URL opcional | notas opcionais",
        "generate": "Envie: Nome | usuário | URL opcional | tamanho opcional",
        "find": "Envie o nome ou trecho para buscar no cofre.",
        "delete": "Envie o nome exato do item que deseja apagar.",
        "change_master": "Envie somente a nova senha mestra. A mensagem será apagada quando possível.",
    }
    return prompts.get(action, "Envie os dados do cofre.")


def _vault_start_input(chat_id: str, action: str) -> None:
    _VAULT_INPUTS[chat_id] = {"action": action, "expires_at": time.time() + VAULT_INPUT_SECONDS}
    send_message(chat_id, _vault_input_prompt(action), vault_keyboard(_vault_session_master(chat_id, False) is not None))


def _vault_split_fields(raw: str) -> list[str]:
    return [part.strip() for part in raw.split("|")]


def _vault_length(raw: str, default: int = 24) -> int:
    try:
        return int(raw.strip())
    except (AttributeError, ValueError):
        return default


def _create_vault_confirmation(chat_id: str, action: str, label: str, description: str) -> str:
    ref = secrets.token_hex(12)
    code = create_pending(
        chat_id,
        action,
        {"ref": ref},
        description,
        user_id=_effective_pending_user_id(),
    )
    _VAULT_CONFIRMATIONS[ref] = {
        "chat_id": str(chat_id),
        "label": label,
        "expires_at": time.time() + VAULT_INPUT_SECONDS,
    }
    return code


def _consume_vault_confirmation(chat_id: str, item: dict[str, Any]) -> str | None:
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
    ref = str(payload.get("ref", ""))
    confirmation = _VAULT_CONFIRMATIONS.pop(ref, None)
    if not confirmation or str(confirmation.get("chat_id")) != str(chat_id):
        return None
    if float(confirmation.get("expires_at", 0)) <= time.time():
        return None
    label = str(confirmation.get("label", "")).strip()
    return label or None


def handle_vault_reveal_confirmation(chat_id: str, item: dict[str, Any]) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    label = _consume_vault_confirmation(chat_id, item)
    if not label:
        send_message(chat_id, "Confirmação do cofre expirada ou inválida. Busque a senha novamente.", vault_keyboard(True))
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        entry = voice_vault.find_entry(master_password, label)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao revelar senha: {exc}", vault_keyboard(False))
        return
    if not entry:
        send_message(chat_id, "Item não encontrado no cofre.", vault_keyboard(True))
        return
    record_event("telegram_vault_reveal", success=True)
    send_message(chat_id, _format_vault_secret(entry), vault_keyboard(True), protect_content=True)


def handle_vault_delete_confirmation(chat_id: str, item: dict[str, Any]) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    label = _consume_vault_confirmation(chat_id, item)
    if not label:
        send_message(chat_id, "Confirmação do cofre expirada ou inválida. Peça para apagar novamente.", vault_keyboard(True))
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        deleted = voice_vault.delete_entry(master_password, label)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao apagar senha: {exc}", vault_keyboard(True))
        return
    record_event("telegram_vault_delete", success=deleted)
    send_message(chat_id, "Senha apagada." if deleted else "Item não encontrado.", vault_keyboard(True))


def _format_vault_entries(entries: list[dict[str, str]], title: str = "Itens no cofre") -> str:
    if not entries:
        return f"{title}\n\nNenhum item encontrado."
    lines = [f"{title}: {len(entries)}", ""]
    for index, item in enumerate(entries[:20], start=1):
        username = item.get("username") or "-"
        url = item.get("url") or "-"
        updated_at = item.get("updated_at") or "-"
        lines.append(
            f"{index}. {item.get('label', '-')}\n"
            f"   Usuário: {username}\n"
            f"   URL: {url}\n"
            f"   Atualizado: {updated_at}"
        )
    if len(entries) > 20:
        lines.append(f"\nMostrando 20 de {len(entries)} itens. Refine a busca.")
    return "\n".join(lines)


def _format_vault_secret(entry: dict[str, str]) -> str:
    lines = [
        f"Conta: {entry.get('label', '-')}",
        f"Usuário: {entry.get('username') or '-'}",
        "",
        str(entry.get("password", "")),
    ]
    if entry.get("url"):
        lines.extend(["", f"URL: {entry['url']}"])
    if entry.get("notes"):
        lines.extend(["", f"Notas: {entry['notes']}"])
    return "\n".join(lines)


def _resolve_vault_entry(master_password: str, query: str) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
    exact = voice_vault.find_entry(master_password, query)
    if exact:
        return exact, []
    matches = voice_vault.search_entries(master_password, query)
    if len(matches) == 1:
        found = voice_vault.find_entry(master_password, matches[0]["label"])
        return found, []
    return None, matches


def handle_vault_unlock(chat_id: str, master_password: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    try:
        count = voice_vault.unlock(master_password)
    except voice_vault.VaultError as exc:
        record_event("telegram_vault_unlock", success=False, error=str(exc))
        send_message(chat_id, f"Não consegui desbloquear o cofre: {exc}", vault_keyboard(False))
        return
    _vault_set_session(chat_id, master_password)
    record_event("telegram_vault_unlock", success=True, entries=count)
    send_message(chat_id, f"Cofre desbloqueado. Itens salvos: {count}.", vault_keyboard(True))


def handle_vault_list(chat_id: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        entries = voice_vault.list_entries(master_password)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao listar o cofre: {exc}", vault_keyboard(False))
        return
    send_message(chat_id, _format_vault_entries(entries), vault_keyboard(True))


def handle_vault_find(chat_id: str, query: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    if not query.strip():
        _vault_start_input(chat_id, "find")
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        entry, matches = _resolve_vault_entry(master_password, query)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao buscar no cofre: {exc}", vault_keyboard(False))
        return
    if entry:
        label = entry.get("label", query).strip() or query.strip()
        code = _create_vault_confirmation(chat_id, "vault_reveal", label, f"Revelar senha do cofre: {label}")
        record_event("telegram_vault_find", success=True, pending=True)
        send_message(
            chat_id,
            f"Encontrei: {label}\n\nConfirme para revelar a senha.\nCódigo: {code}\nUse: /confirmar {code}",
            confirmation_keyboard(code),
        )
        return
    send_message(chat_id, _format_vault_entries(matches, "Resultados da busca"), vault_keyboard(True))


def handle_vault_save_existing(chat_id: str, raw: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    if not raw.strip():
        _vault_start_input(chat_id, "add")
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    fields = _vault_split_fields(raw)
    if len(fields) < 3 or not fields[0] or not fields[2]:
        send_message(chat_id, "Uso: /senhas salvar NOME | USUARIO | SENHA | URL | NOTAS", vault_keyboard(True))
        return
    label = fields[0]
    username = fields[1] if len(fields) > 1 else ""
    password = fields[2]
    url = fields[3] if len(fields) > 3 else ""
    notes = fields[4] if len(fields) > 4 else ""
    try:
        voice_vault.save_entry(master_password, label, username, password, url, notes)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao salvar senha: {exc}", vault_keyboard(True))
        return
    record_event("telegram_vault_save", success=True)
    send_message(chat_id, f"Senha salva/atualizada: {label}", vault_keyboard(True))


def handle_vault_generate(chat_id: str, raw: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    raw = raw.strip()
    if not raw or raw.isdigit():
        length = _vault_length(raw, 24)
        password = voice_vault.generate_password(length)
        send_message(chat_id, f"Senha forte gerada:\n{password}\n\nNão foi salva no cofre.", protect_content=True)
        return

    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    fields = _vault_split_fields(raw)
    label = fields[0] if fields else ""
    if not label:
        send_message(chat_id, "Uso: /senhas gerar NOME | USUARIO | URL | TAMANHO", vault_keyboard(True))
        return
    username = fields[1] if len(fields) > 1 else ""
    url = fields[2] if len(fields) > 2 else ""
    length_text = fields[3] if len(fields) > 3 else ""
    notes = fields[4] if len(fields) > 4 else ""
    if len(fields) == 3 and fields[2].isdigit():
        url = ""
        length_text = fields[2]
    password = voice_vault.generate_password(_vault_length(length_text, 24))
    try:
        voice_vault.save_entry(master_password, label, username, password, url, notes)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao salvar senha gerada: {exc}", vault_keyboard(True))
        return
    code = _create_vault_confirmation(chat_id, "vault_reveal", label, f"Revelar senha gerada do cofre: {label}")
    record_event("telegram_vault_generate_save", success=True, pending=True)
    send_message(
        chat_id,
        f"Senha gerada e salva em {label}.\n\nConfirme para revelar.\nCódigo: {code}\nUse: /confirmar {code}",
        confirmation_keyboard(code),
    )


def handle_vault_delete(chat_id: str, label: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    if not label.strip():
        _vault_start_input(chat_id, "delete")
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        entry = voice_vault.find_entry(master_password, label)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao apagar senha: {exc}", vault_keyboard(True))
        return
    if not entry:
        send_message(chat_id, "Item não encontrado.", vault_keyboard(True))
        return
    resolved_label = entry.get("label", label).strip() or label.strip()
    code = _create_vault_confirmation(chat_id, "vault_delete", resolved_label, f"Apagar senha do cofre: {resolved_label}")
    record_event("telegram_vault_delete_request", success=True)
    send_message(
        chat_id,
        f"Confirme para apagar: {resolved_label}\nCódigo: {code}\nUse: /confirmar {code}",
        confirmation_keyboard(code),
    )


def handle_vault_change_master(chat_id: str, new_master_password: str) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    if not new_master_password.strip():
        _vault_start_input(chat_id, "change_master")
        return
    master_password = _vault_require_master(chat_id)
    if not master_password:
        return
    try:
        count = voice_vault.change_master_password(master_password, new_master_password)
    except voice_vault.VaultError as exc:
        send_message(chat_id, f"Falha ao trocar senha mestra: {exc}", vault_keyboard(True))
        return
    _vault_set_session(chat_id, new_master_password)
    record_event("telegram_vault_change_master", success=True, entries=count)
    send_message(chat_id, f"Senha mestra alterada. Itens preservados: {count}.", vault_keyboard(True))


def handle_vault_command(chat_id: str, text: str, message_id: object = None) -> None:
    if not require_remote_action(chat_id, "vault"):
        return
    _command, _separator, rest = text.partition(" ")
    rest = rest.strip()
    if not rest or rest.lower() in {"menu", "abrir"}:
        unlocked = _vault_session_master(chat_id, refresh=False) is not None
        send_message(chat_id, vault_menu_text(chat_id), vault_keyboard(unlocked))
        return

    action, _separator, payload = rest.partition(" ")
    action = action.strip().lower()
    payload = payload.strip()
    if action in {"ajuda", "help"}:
        send_message(chat_id, vault_help_text(), vault_keyboard(_vault_session_master(chat_id, False) is not None))
        return
    if action in {"desbloquear", "unlock"}:
        if payload:
            delete_message(chat_id, message_id)
            handle_vault_unlock(chat_id, payload)
        else:
            _vault_start_input(chat_id, "unlock")
        return
    if action in {"bloquear", "lock"}:
        _vault_lock(chat_id)
        send_message(chat_id, "Cofre bloqueado.", vault_keyboard(False))
        return
    if action in {"listar", "lista", "list"}:
        handle_vault_list(chat_id)
        return
    if action in {"buscar", "procurar", "get"}:
        handle_vault_find(chat_id, payload)
        return
    if action in {"salvar", "adicionar", "add"}:
        if payload:
            delete_message(chat_id, message_id)
        handle_vault_save_existing(chat_id, payload)
        return
    if action in {"gerar", "gen"}:
        handle_vault_generate(chat_id, payload)
        return
    if action in {"apagar", "remover", "delete", "del"}:
        handle_vault_delete(chat_id, payload)
        return
    if action in {"trocar", "mestra", "change-master"}:
        if payload:
            delete_message(chat_id, message_id)
        handle_vault_change_master(chat_id, payload)
        return
    send_message(chat_id, vault_help_text(), vault_keyboard(_vault_session_master(chat_id, False) is not None))


def handle_vault_input(chat_id: str, text: str, message_id: object = None) -> bool:
    state = _VAULT_INPUTS.get(chat_id)
    if not state:
        return False
    if text.startswith("/"):
        return False

    action = str(state.get("action", ""))
    sensitive = action in {"unlock", "add", "change_master"}
    if float(state.get("expires_at", 0)) <= time.time():
        _VAULT_INPUTS.pop(chat_id, None)
        if sensitive:
            delete_message(chat_id, message_id)
        send_message(chat_id, "Entrada do cofre expirada. Abra /senhas novamente.")
        return True

    _VAULT_INPUTS.pop(chat_id, None)
    if sensitive:
        delete_message(chat_id, message_id)

    if action == "unlock":
        handle_vault_unlock(chat_id, text)
    elif action == "add":
        handle_vault_save_existing(chat_id, text)
    elif action == "generate":
        handle_vault_generate(chat_id, text)
    elif action == "find":
        handle_vault_find(chat_id, text)
    elif action == "delete":
        handle_vault_delete(chat_id, text)
    elif action == "change_master":
        handle_vault_change_master(chat_id, text)
    else:
        send_message(chat_id, "Entrada do cofre não reconhecida.", vault_keyboard(_vault_session_master(chat_id, False) is not None))
    return True


def handle_vault_callback(chat_id: str, callback_id: str, data: str) -> None:
    if not require_remote_action(chat_id, "vault", callback_id):
        return
    action = data.split(":", 1)[1] if ":" in data else "menu"
    if action == "menu":
        answer_callback(callback_id, "Cofre.")
        unlocked = _vault_session_master(chat_id, refresh=False) is not None
        send_message(chat_id, vault_menu_text(chat_id), vault_keyboard(unlocked))
        return
    if action == "help":
        answer_callback(callback_id, "Ajuda.")
        send_message(chat_id, vault_help_text(), vault_keyboard(_vault_session_master(chat_id, False) is not None))
        return
    if action == "unlock":
        answer_callback(callback_id, "Desbloquear.")
        _vault_start_input(chat_id, "unlock")
        return
    if action == "lock":
        answer_callback(callback_id, "Bloqueado.")
        _vault_lock(chat_id)
        send_message(chat_id, "Cofre bloqueado.", vault_keyboard(False))
        return
    if action == "list":
        answer_callback(callback_id, "Listar.")
        handle_vault_list(chat_id)
        return
    if action == "find":
        answer_callback(callback_id, "Buscar.")
        if _vault_require_master(chat_id):
            _vault_start_input(chat_id, "find")
        return
    if action == "add":
        answer_callback(callback_id, "Adicionar.")
        if _vault_require_master(chat_id):
            _vault_start_input(chat_id, "add")
        return
    if action == "generate":
        answer_callback(callback_id, "Gerar.")
        if _vault_require_master(chat_id):
            _vault_start_input(chat_id, "generate")
        return
    if action == "quickgen":
        answer_callback(callback_id, "Senha gerada.")
        handle_vault_generate(chat_id, "")
        return
    if action == "delete":
        answer_callback(callback_id, "Apagar.")
        if _vault_require_master(chat_id):
            _vault_start_input(chat_id, "delete")
        return
    if action == "change_master":
        answer_callback(callback_id, "Trocar mestra.")
        if _vault_require_master(chat_id):
            _vault_start_input(chat_id, "change_master")
        return
    answer_callback(callback_id, "Comando desconhecido.")


def handle_message(message: dict[str, Any]) -> None:
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    chat_id = str(chat.get("id", ""))
    user_id = str(sender.get("id", ""))
    if not is_authorized_sender(chat_id, user_id):
        record_event("telegram_control_denied", chat_id=chat_id, user_id=user_id)
        return

    token = _AUTHORIZED_USER_ID.set(user_id)
    try:
        _handle_authorized_message(message, chat_id, user_id)
    finally:
        _AUTHORIZED_USER_ID.reset(token)


def _handle_authorized_message(message: dict[str, Any], chat_id: str, user_id: str) -> None:

    text = str(message.get("text") or "").strip()
    if not text or text in {"/start", "/help"}:
        send_message(chat_id, command_help(), main_keyboard())
        return
    message_id = message.get("message_id")
    if handle_vault_input(chat_id, text, message_id):
        return
    command = text.split(maxsplit=1)[0]
    if command in {"/senhas", "/senha", "/cofre"}:
        handle_vault_command(chat_id, text, message_id)
        return
    if text.startswith("/status"):
        send_message(chat_id, status_text())
        return
    if text.startswith("/cmd "):
        handle_cmd(chat_id, text, user_id)
        return
    if text.startswith("/arquivo "):
        handle_file_request(chat_id, text.split(maxsplit=1)[1], user_id)
        return
    if text.startswith("/ia "):
        handle_ai(chat_id, text, user_id)
        return
    if command in {"/estudar", "/estudo"}:
        handle_study(chat_id, text, "estudar")
        return
    if command == "/explicar":
        handle_study(chat_id, text, "explicar")
        return
    if command == "/resumir":
        handle_study(chat_id, text, "resumir")
        return
    if command == "/quiz":
        handle_study(chat_id, text, "quiz")
        return
    if text.startswith("/limparia"):
        handle_ai_clear(chat_id)
        return
    if text.startswith("/pendentes"):
        send_message(chat_id, pending_text(chat_id, user_id))
        return
    if text.startswith("/confirmar "):
        handle_confirm(chat_id, text, user_id)
        return
    if text.startswith("/cancelar "):
        handle_cancel(chat_id, text, user_id)
        return
    if text.startswith("/rede") or text.startswith("/scan"):
        handle_rede(chat_id, text)
        return
    if text.startswith("/banip "):
        _ok, response = apply_telegram_ban("ip", text.split(maxsplit=1)[1])
        send_message(chat_id, response)
        return
    if text.startswith("/banmac "):
        _ok, response = apply_telegram_ban("mac", text.split(maxsplit=1)[1])
        send_message(chat_id, response)
        return
    if text.startswith("/banidos"):
        send_message(chat_id, list_bans_text())
        return
    if not text.startswith("/"):
        handle_ai(chat_id, f"/ia {text}", user_id)
        return
    send_message(chat_id, command_help(), main_keyboard())


def handle_callback(callback: dict[str, Any]) -> None:
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    sender = callback.get("from") or {}
    chat_id = str(chat.get("id", ""))
    user_id = str(sender.get("id", ""))
    callback_id = str(callback.get("id", ""))
    if not is_authorized_sender(chat_id, user_id):
        answer_callback(callback_id, "Chat nao autorizado.")
        record_event("telegram_control_denied", chat_id=chat_id, user_id=user_id)
        return

    token = _AUTHORIZED_USER_ID.set(user_id)
    try:
        _handle_authorized_callback(callback_id, chat_id, user_id, callback)
    finally:
        _AUTHORIZED_USER_ID.reset(token)


def _handle_authorized_callback(
    callback_id: str,
    chat_id: str,
    user_id: str,
    callback: dict[str, Any],
) -> None:

    data = str(callback.get("data") or "")
    if data.startswith("vault:"):
        handle_vault_callback(chat_id, callback_id, data)
        return
    if data.startswith("ai:"):
        handle_ai_callback(chat_id, callback_id, data)
        return
    if data == "menu:home":
        answer_callback(callback_id, "Menu.")
        send_message(chat_id, command_help(), main_keyboard())
        return
    if data == "menu:status":
        answer_callback(callback_id, "Status.")
        send_message(chat_id, status_text(), status_keyboard())
        return
    if data == "menu:services":
        answer_callback(callback_id, "Serviços.")
        send_message(chat_id, services_menu_text(), services_keyboard())
        return
    if data == "menu:rede":
        answer_callback(callback_id, "Rede.")
        send_message(chat_id, network_menu_text(), network_keyboard())
        return
    if data == "menu:arquivo":
        answer_callback(callback_id, "Arquivo.")
        send_message(chat_id, file_menu_text(), file_keyboard())
        return
    if data == "menu:terminal":
        answer_callback(callback_id, "Terminal.")
        send_message(chat_id, terminal_menu_text(), terminal_keyboard())
        return
    if data == "menu:pendentes":
        answer_callback(callback_id, "Pendentes.")
        send_message(chat_id, pending_text(chat_id, user_id), main_keyboard())
        return
    if data == "menu:ia":
        answer_callback(callback_id, "IA.")
        send_message(chat_id, ai_menu_text(), ai_keyboard())
        return
    if data == "net:scan":
        answer_callback(callback_id, "Escaneando rede.")
        handle_rede(chat_id, "/rede")
        return
    if data == "net:bans":
        answer_callback(callback_id, "Banidos.")
        send_message(chat_id, list_bans_text(), network_keyboard())
        return
    if data == "term:status":
        answer_callback(callback_id, "Status.")
        send_message(chat_id, status_text(), terminal_keyboard())
        return
    if data == "term:help":
        answer_callback(callback_id, "Ajuda.")
        send_message(chat_id, terminal_menu_text(), terminal_keyboard())
        return
    if data == "file:downloads":
        answer_callback(callback_id, "Downloads.")
        request_confirmation(chat_id, "send_path", {"path": "~/Downloads"}, "Enviar pasta Downloads", user_id)
        return
    if data == "file:documents":
        answer_callback(callback_id, "Documentos.")
        request_confirmation(chat_id, "send_path", {"path": "~/Documentos"}, "Enviar pasta Documentos", user_id)
        return
    if data == "file:help":
        answer_callback(callback_id, "Ajuda.")
        send_message(chat_id, file_menu_text(), file_keyboard())
        return
    if data in {"svc:up", "svc:down", "svc:restart"}:
        service_action = data.split(":", 1)[1]
        answer_callback(callback_id, "Confirmação criada.")
        request_confirmation(
            chat_id,
            "bunker_services",
            {"operation": service_action},
            f"Serviços do Kali Bunker: {service_action}",
            user_id,
        )
        return
    if data.startswith("confirm:"):
        answer_callback(callback_id, "Executando.")
        execute_pending_action(chat_id, data.split(":", 1)[1], user_id)
        return
    if data.startswith("cancel:"):
        code = data.split(":", 1)[1]
        cancelled = cancel_pending(chat_id, code, user_id=user_id)
        answer_callback(callback_id, "Cancelado." if cancelled else "Não encontrado.")
        send_message(chat_id, "Ação cancelada." if cancelled else "Código não encontrado.")
        return
    if data.startswith("ban_ip:"):
        ok, response = apply_telegram_ban("ip", data.split(":", 1)[1])
    elif data.startswith("ban_mac:"):
        ok, response = apply_telegram_ban("mac", data.split(":", 1)[1])
    else:
        ok, response = False, "Comando desconhecido."
    answer_callback(callback_id, "Bloqueado." if ok else "Falha no bloqueio.")
    send_message(chat_id, response)


def polling_config_error() -> str | None:
    if not TELEGRAM_BOT_TOKEN:
        return "TELEGRAM_BOT_TOKEN nao configurado."
    if not allowed_chat_ids():
        return "TELEGRAM_ALLOWED_CHAT_IDS nao configurado."
    if not allowed_user_ids():
        return "TELEGRAM_ALLOWED_USER_IDS nao configurado."
    return None


def run_loop() -> None:
    config_error = polling_config_error()
    if config_error:
        raise SystemExit(config_error)

    offset = load_telegram_offset()
    consecutive_failures = 0
    while True:
        try:
            updates = get_updates(offset)
            if updates is None:
                consecutive_failures += 1
                time.sleep(polling_retry_delay(consecutive_failures))
                continue
            consecutive_failures = 0
            for update in updates:
                claimed_offset = process_update_at_most_once(update)
                if claimed_offset is not None:
                    offset = claimed_offset
        except Exception as exc:
            print(f"[telegram-control] erro no loop: {exc}")
            record_event("telegram_control_error", error=str(exc))
            time.sleep(max(1, TELEGRAM_POLL_INTERVAL_SECONDS))


if __name__ == "__main__":
    run_loop()
