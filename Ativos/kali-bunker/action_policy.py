#!/usr/bin/env python3
"""Politica deterministica para acoes remotas confirmadas.

A IA pode sugerir uma acao, mas somente este modulo transforma a sugestao em
um envelope canonico aceito pelo executor. Ele nao executa comandos nem acessa
rede/estado, portanto a mesma entrada sempre produz a mesma decisao e digest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any


ACTION_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]{0,63}$")
REFERENCE_RE = re.compile(r"^[A-Fa-f0-9]{24,64}$")
REMOTE_SERVICE_UNITS = {
    "BT": "bt-alarm.service",
    "AUTH": "monitor-auth.service",
    "SYS": "monitor-recursos.service",
    "WIFI": "monitor-wifi.service",
    "FILE": "monitor-arquivos.service",
    "USB": "usbguard.service",
    "BAN": "fail2ban.service",
}
REMOTE_SERVICE_CODES = frozenset((*REMOTE_SERVICE_UNITS, "MAIL"))
REMOTE_SERVICE_ACTIONS = frozenset({"start", "stop", "restart"})
BUNKER_SERVICE_OPERATIONS = frozenset({"up", "down", "restart", "status"})
EMPTY_PAYLOAD_ACTIONS = frozenset({"webcam", "network_scan", "purge_bot_messages"})
MAX_CANONICAL_ACTION_BYTES = 20_000


class PolicyViolation(ValueError):
    """A acao ou os parametros nao pertencem a politica permitida."""


def _require_exact_keys(payload: dict[str, Any], expected: set[str]) -> None:
    actual = set(payload)
    if actual != expected:
        raise PolicyViolation(
            "parametros invalidos: esperado "
            f"{sorted(expected)}, recebido {sorted(str(key) for key in actual)}"
        )


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise PolicyViolation(f"{field} deve ser texto")
    if not value or len(value) > maximum or "\x00" in value:
        raise PolicyViolation(f"{field} vazio, grande demais ou com byte nulo")
    return value


def validate_action_payload(action: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Valida e normaliza uma acao usando somente regras allowlist."""
    if not isinstance(action, str) or not ACTION_NAME_RE.fullmatch(action):
        raise PolicyViolation("nome de acao invalido")
    if not isinstance(payload, dict):
        raise PolicyViolation("payload deve ser um objeto")

    if action == "shell":
        _require_exact_keys(payload, {"command"})
        normalized = {"command": _bounded_text(payload.get("command"), "command", 8192)}
    elif action == "send_path":
        _require_exact_keys(payload, {"path"})
        normalized = {"path": _bounded_text(payload.get("path"), "path", 4096)}
    elif action == "install_package":
        _require_exact_keys(payload, {"package"})
        package = _bounded_text(payload.get("package"), "package", 64)
        if not PACKAGE_NAME_RE.fullmatch(package):
            raise PolicyViolation("nome de pacote invalido")
        normalized = {"package": package}
    elif action == "service":
        _require_exact_keys(payload, {"service_action", "service_code"})
        service_action = _bounded_text(payload.get("service_action"), "service_action", 16).lower()
        service_code = _bounded_text(payload.get("service_code"), "service_code", 16).upper()
        if service_action not in REMOTE_SERVICE_ACTIONS or service_code not in REMOTE_SERVICE_CODES:
            raise PolicyViolation("acao ou codigo de servico fora da allowlist")
        normalized = {"service_action": service_action, "service_code": service_code}
    elif action == "bunker_services":
        _require_exact_keys(payload, {"operation"})
        operation = _bounded_text(payload.get("operation"), "operation", 16).lower()
        if operation not in BUNKER_SERVICE_OPERATIONS:
            raise PolicyViolation("operacao do bunker fora da allowlist")
        normalized = {"operation": operation}
    elif action in {"vault_reveal", "vault_delete"}:
        _require_exact_keys(payload, {"ref"})
        reference = _bounded_text(payload.get("ref"), "ref", 64)
        if not REFERENCE_RE.fullmatch(reference):
            raise PolicyViolation("referencia de cofre invalida")
        normalized = {"ref": reference}
    elif action in EMPTY_PAYLOAD_ACTIONS:
        _require_exact_keys(payload, set())
        normalized = {}
    else:
        raise PolicyViolation(f"acao fora da allowlist: {action}")

    # Garante que o envelope continue representavel de forma portavel em JSON.
    try:
        encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise PolicyViolation("payload nao canonizavel") from exc
    if len(encoded.encode("utf-8")) > MAX_CANONICAL_ACTION_BYTES:
        raise PolicyViolation("payload canonico grande demais")
    return action, json.loads(encoded)


def canonical_action_bytes(action: str, payload: dict[str, Any]) -> bytes:
    """Produz a representacao canonica versionada de uma acao valida."""
    normalized_action, normalized_payload = validate_action_payload(action, payload)
    document = {
        "action": normalized_action,
        "params": normalized_payload,
        "policy_version": 1,
    }
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_action_digest(action: str, payload: dict[str, Any]) -> str:
    """Retorna SHA-256 do envelope canonico versionado."""
    return hashlib.sha256(canonical_action_bytes(action, payload)).hexdigest()


def validate_action_digest(action: str, payload: dict[str, Any], expected: str) -> bool:
    """Compara digest sem atalho temporal observavel."""
    if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
        return False
    actual = canonical_action_digest(action, payload)
    return hmac.compare_digest(actual, expected)
