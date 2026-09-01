#!/usr/bin/env python3
"""Controle remoto autorizado para o bot Telegram do Kali Bunker."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import secrets
import shlex
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

from action_policy import (
    PolicyViolation,
    REMOTE_SERVICE_UNITS,
    canonical_action_digest,
    validate_action_digest,
    validate_action_payload,
)
from bunker_audit import STATE_DIR, record_event
from bunker_config import get_config, get_int
from state_utils import atomic_write_json, exclusive_file_lock


PENDING_FILE = STATE_DIR / "remote-pending.json"
AI_CHAT_HISTORY_FILE = STATE_DIR / "ai-chat-history.json"
AI_MEMORY_FILE = STATE_DIR / "ai-memory.json"
REMOTE_LOG = STATE_DIR / "remote-actions.jsonl"
DEFAULT_TIMEOUT = get_int("REMOTE_COMMAND_TIMEOUT_SECONDS", 60)
MAX_OUTPUT_CHARS = get_int("REMOTE_COMMAND_MAX_OUTPUT_CHARS", 3500)
MAX_UPLOAD_MB = get_int("REMOTE_MAX_UPLOAD_MB", 45)
PENDING_TTL_SECONDS = max(1, get_int("REMOTE_PENDING_TTL_SECONDS", 300))
REMOTE_SHELL_ENABLED = get_int("REMOTE_SHELL_ENABLED", 0) == 1
REMOTE_FILE_EXPORT_ENABLED = get_int("REMOTE_FILE_EXPORT_ENABLED", 0) == 1
REMOTE_PACKAGE_INSTALL_ENABLED = get_int("REMOTE_PACKAGE_INSTALL_ENABLED", 0) == 1
REMOTE_WEBCAM_ENABLED = get_int("REMOTE_WEBCAM_ENABLED", 0) == 1
REMOTE_VAULT_ENABLED = get_int("REMOTE_VAULT_ENABLED", 0) == 1
REMOTE_EXPORT_ALLOWED_ROOTS = get_config("REMOTE_EXPORT_ALLOWED_ROOTS")
AI_CHAT_HISTORY_MESSAGES = get_int("KALI_BUNKER_AI_HISTORY_MESSAGES", 16)
AI_CHAT_MESSAGE_MAX_CHARS = get_int("KALI_BUNKER_AI_MESSAGE_MAX_CHARS", 2500)
AI_MEMORY_MAX_ITEMS = get_int("KALI_BUNKER_AI_MEMORY_MAX_ITEMS", 300)
AI_MEMORY_ITEM_MAX_CHARS = get_int("KALI_BUNKER_AI_MEMORY_ITEM_MAX_CHARS", 20000)
AI_INPUT_MAX_CHARS = get_int("KALI_BUNKER_AI_INPUT_MAX_CHARS", 12000)
AI_MAX_OUTPUT_TOKENS = get_int("KALI_BUNKER_AI_MAX_OUTPUT_TOKENS", 900)
AI_FAST_LOCAL_RESPONSES = get_config("KALI_BUNKER_AI_FAST_LOCAL", "1") != "0"
OPENAI_TIMEOUT_SECONDS = get_int("KALI_BUNKER_AI_TIMEOUT_SECONDS", 45)
OPENAI_API_KEY = get_config("OPENAI_API_KEY")
AI_MODEL = get_config("KALI_BUNKER_AI_MODEL", "gpt-5.5")
AI_PROVIDER = get_config("KALI_BUNKER_AI_PROVIDER", get_config("AI_PROVIDER", "auto")).strip().lower()
GEMINI_API_KEY = get_config("GEMINI_API_KEY")
GEMINI_MODEL = get_config("GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_FALLBACK_MODEL = get_config("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")
DEFAULT_SSH_PROFILE = get_config(
    "KALI_BUNKER_DEFAULT_SSH",
    "voide@100.87.201.41",
).strip()
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
HOME = Path.home()
OPENAI_AUTH_DISABLED = False
_OPENAI_AUTH_DISABLED_AT: float = 0.0
_OPENAI_AUTH_COOLDOWN = 300  # 5 minutos antes de tentar a API novamente
ARITHMETIC_RE = re.compile(r"(?<!\S)(?:\d+(?:\s*[\+\-\*/]\s*\d+)+)(?!\S)")
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]{0,63}$")
INSTALL_TRIGGER_RE = re.compile(
    r"^(?:instalar|instale|instala|install|baixar|baixe|download)\s+(?P<package>.+)$",
    re.IGNORECASE,
)
SEND_PATH_PHRASE_RE = re.compile(
    r"^\s*(?:por favor\s+)?"
    r"(?:(?:manda|mande|envia|envie)\s+(?:pra|para)\s+mim|(?:me\s+)?(?:manda|mande|envia|envie)|enviar)"
    r"\s+(?:(?:o|a|os|as|um|uma)\s+)?(?:(?P<kind>arquivo|pasta|documento|pdf)\s+)?(?P<path>.+?)\s*$",
    re.IGNORECASE,
)
CODE_BLOCK_RE = re.compile(
    r"^\s*```(?P<lang>[A-Za-z0-9_+-]*)\s*\n(?P<body>.*?)\n```\s*$",
    re.DOTALL,
)
REMOTE_ACTION_FEATURES = {
    "shell": ("REMOTE_SHELL_ENABLED", "terminal remoto"),
    "send_path": ("REMOTE_FILE_EXPORT_ENABLED", "exportação remota de arquivos"),
    "install_package": ("REMOTE_PACKAGE_INSTALL_ENABLED", "instalação remota de pacotes"),
    "webcam": ("REMOTE_WEBCAM_ENABLED", "webcam remota"),
    "vault": ("REMOTE_VAULT_ENABLED", "cofre remoto"),
    "vault_reveal": ("REMOTE_VAULT_ENABLED", "cofre remoto"),
    "vault_delete": ("REMOTE_VAULT_ENABLED", "cofre remoto"),
}
SHELL_FORBIDDEN_RE = re.compile(r"[\x00-\x1f\x7f;|&<>`]|\$\(")
SENSITIVE_EXPORT_PARTS = {
    ".ssh",
    ".gnupg",
    ".config",
    ".aws",
    ".azure",
    ".docker",
    ".kube",
    ".password-store",
    "credentials",
    "secrets",
    "tokens",
}
SENSITIVE_EXPORT_NAMES = {
    ".env",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "key4.db",
    "login data",
    "token.json",
    "tokens.json",
}
SENSITIVE_EXPORT_SUFFIXES = (".key", ".kdbx", ".p12", ".pem", ".pfx")
SENSITIVE_EXPORT_WORD_RE = re.compile(
    r"(?:^|[._-])(?:credential|credentials|secret|secrets|token|tokens)(?:[._-]|$)",
    re.IGNORECASE,
)
EXPORT_ARCHIVE_PREFIX = ".kali-bunker-export-"


class RemoteFeatureDisabled(PermissionError):
    """Raised when a privileged remote feature was not explicitly enabled."""


def remote_action_enabled(action: str) -> bool:
    feature = REMOTE_ACTION_FEATURES.get(action)
    if feature is None:
        return True
    return bool(globals().get(feature[0], False))


def remote_action_disabled_message(action: str) -> str:
    variable, label = REMOTE_ACTION_FEATURES.get(
        action,
        ("UNKNOWN_REMOTE_FEATURE", "recurso remoto"),
    )
    return f"{label.capitalize()} desabilitado por segurança. Configure {variable}=1 localmente para habilitar."


def ensure_remote_action_enabled(action: str) -> None:
    if not remote_action_enabled(action):
        raise RemoteFeatureDisabled(remote_action_disabled_message(action))

SERVICE_KEYWORDS = {
    "gmail": "MAIL",
    "mail": "MAIL",
    "email": "MAIL",
    "wifi": "WIFI",
    "rede": "WIFI",
    "network": "WIFI",
    "bluetooth": "BT",
    "bt": "BT",
    "auth": "AUTH",
    "autenticacao": "AUTH",
    "autenticação": "AUTH",
    "arquivos": "FILE",
    "files": "FILE",
    "file": "FILE",
    "usb": "USB",
    "ban": "BAN",
    "fail2ban": "BAN",
    "sys": "SYS",
    "recursos": "SYS",
    "system": "SYS",
}

def _now() -> int:
    return int(time.time())


def _normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", "ignore").decode("ascii").lower()


def _extract_topic(prompt: str, prefixes: list[str]) -> str:
    normalized = _normalize_text(prompt).strip()
    for prefix in prefixes:
        if normalized.startswith(prefix):
            topic = prompt[len(prefix):].strip(" \t:-,.;!?")
            return topic or prompt.strip()
        if prefix in normalized:
            index = normalized.find(prefix)
            topic = prompt[index + len(prefix):].strip(" \t:-,.;!?")
            return topic or prompt.strip()
    return prompt.strip()


def _has_any(normalized: str, words: tuple[str, ...]) -> bool:
    return any(word in normalized for word in words)


def _is_greeting(normalized: str) -> bool:
    words = normalized.split()
    if len(words) > 4:
        return False
    if any(phrase in normalized for phrase in ("bom dia", "boa tarde", "boa noite")):
        return True
    return bool(re.search(r"^(?:oi|ola|eae|olá)(?:\s+voz|bot|ai)?\b", normalized))


def _payload_after_keyword(prompt: str, keywords: tuple[str, ...]) -> str:
    normalized = _normalize_text(prompt)
    for keyword in keywords:
        index = normalized.find(keyword)
        if index >= 0:
            return prompt[index + len(keyword):].strip(" \t:-,.;!?")
    return prompt.strip()


def _topic_or_default(prompt: str, keywords: tuple[str, ...], default: str = "seu tema") -> str:
    topic = _payload_after_keyword(prompt, keywords)
    return topic or default


def _strong_password(length: int = 18) -> str:
    length = min(max(length, 12), 64)
    alphabet = string.ascii_letters + string.digits + "!@#$%&*_-+="
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(char.islower() for char in password)
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
            and any(char in "!@#$%&*_-+=" for char in password)
        ):
            return password


def _markdown_table(prompt: str) -> str:
    topic = _topic_or_default(prompt, ("tabela markdown", "tabela", "markdown"), "comparacao")
    return (
        f"Tabela Markdown para {topic}:\n\n"
        "| Item | Descricao | Prioridade |\n"
        "|---|---|---|\n"
        "| 1 | Definir objetivo | Alta |\n"
        "| 2 | Separar dados principais | Media |\n"
        "| 3 | Revisar resultado | Alta |"
    )


def _validate_json(payload: str) -> str:
    if not payload:
        return "Envie assim: validar json {\"ok\": true}"
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        return f"JSON invalido: linha {exc.lineno}, coluna {exc.colno}. Motivo: {exc.msg}."
    kind = type(parsed).__name__
    return f"JSON valido. Tipo principal: {kind}."


def _percentage_response(prompt: str) -> str | None:
    numbers = [float(value.replace(",", ".")) for value in re.findall(r"-?\d+(?:[,.]\d+)?", prompt)]
    normalized = _normalize_text(prompt)
    if len(numbers) >= 2 and _has_any(normalized, ("porcent", "%")):
        part, total = numbers[0], numbers[1]
        if total == 0:
            return "Nao da para calcular porcentagem com total zero."
        return f"{part:g} de {total:g} = {(part / total) * 100:.2f}%."
    return None


def _rule_of_three_response(prompt: str) -> str | None:
    numbers = [float(value.replace(",", ".")) for value in re.findall(r"-?\d+(?:[,.]\d+)?", prompt)]
    normalized = _normalize_text(prompt)
    if len(numbers) >= 3 and "regra de tres" in normalized:
        a, b, c = numbers[:3]
        if a == 0:
            return "Nao da para aplicar regra de tres com o primeiro valor zero."
        return f"Regra de tres: se {a:g} = {b:g}, entao {c:g} = {(b * c) / a:.2f}."
    return None


def _temperature_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    match = re.search(r"(-?\d+(?:[,.]\d+)?)", prompt)
    if not match or not _has_any(normalized, ("celsius", "fahrenheit", "temperatura")):
        return None
    value = float(match.group(1).replace(",", "."))
    if "fahrenheit" in normalized or " f" in f" {normalized} ":
        celsius = (value - 32) * 5 / 9
        return f"{value:g} °F = {celsius:.2f} °C."
    fahrenheit = value * 9 / 5 + 32
    return f"{value:g} °C = {fahrenheit:.2f} °F."


def _file_size_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    match = re.search(r"(\d+(?:[,.]\d+)?)\s*(kb|mb|gb|tb|bytes?|b)", normalized)
    if not match or not _has_any(normalized, ("tamanho", "arquivo", "kb", "mb", "gb", "tb")):
        return None
    value = float(match.group(1).replace(",", "."))
    unit = match.group(2)
    multipliers = {"b": 1, "byte": 1, "bytes": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
    bytes_value = value * multipliers[unit]
    return (
        f"{value:g} {unit.upper()} = {bytes_value:,.0f} bytes\n"
        f"= {bytes_value / 1024:.2f} KB\n"
        f"= {bytes_value / 1024**2:.2f} MB\n"
        f"= {bytes_value / 1024**3:.2f} GB"
    )


def _time_conversion_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    match = re.search(r"(\d+(?:[,.]\d+)?)\s*(segundos?|minutos?|horas?|dias?)", normalized)
    if not match or not _has_any(normalized, ("converter tempo", "segundo", "minuto", "hora", "dia")):
        return None
    value = float(match.group(1).replace(",", "."))
    unit = match.group(2)
    seconds = value
    if unit.startswith("minuto"):
        seconds = value * 60
    elif unit.startswith("hora"):
        seconds = value * 3600
    elif unit.startswith("dia"):
        seconds = value * 86400
    return f"{value:g} {unit} = {seconds:.0f} segundos = {seconds / 60:.2f} minutos = {seconds / 3600:.2f} horas."


def utility_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if _has_any(normalized, ("senha forte", "gerar senha", "criar senha")):
        match = re.search(r"\b(\d{2,})\b", prompt)
        length = int(match.group(1)) if match else 18
        return f"Senha forte gerada:\n{_strong_password(length)}\n\nGuarde em um gerenciador de senhas."

    if _has_any(normalized, ("sha256", "hash")):
        payload = _payload_after_keyword(prompt, ("sha256", "hash"))
        if not payload:
            return "Envie assim: sha256 texto que voce quer calcular."
        return f"SHA256:\n{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"

    if _has_any(normalized, ("base64 encode", "codificar base64")):
        payload = _payload_after_keyword(prompt, ("base64 encode", "codificar base64"))
        if not payload:
            return "Envie assim: base64 encode seu texto."
        return base64.b64encode(payload.encode("utf-8")).decode("ascii")

    if _has_any(normalized, ("base64 decode", "decodificar base64")):
        payload = _payload_after_keyword(prompt, ("base64 decode", "decodificar base64"))
        if not payload:
            return "Envie assim: base64 decode c2V1IHRleHRv"
        try:
            return base64.b64decode(payload.encode("ascii"), validate=True).decode("utf-8")
        except Exception:
            return "Base64 invalido ou texto decodificado nao e UTF-8."

    if "validar json" in normalized:
        return _validate_json(_payload_after_keyword(prompt, ("validar json",)))

    for converter in (_percentage_response, _rule_of_three_response, _temperature_response, _file_size_response, _time_conversion_response):
        response = converter(prompt)
        if response:
            return response

    if _has_any(normalized, ("timestamp", "unix time")):
        now = datetime.now()
        return f"Timestamp atual: {int(now.timestamp())}\nData local: {now.strftime('%d/%m/%Y %H:%M:%S')}."

    if _has_any(normalized, ("flashcard", "flashcards")):
        topic = _topic_or_default(prompt, ("flashcards", "flashcard", "sobre", "de"))
        return (
            f"Flashcards sobre {topic}:\n"
            "1. Frente: Qual e a definicao principal? | Verso: explique em uma frase.\n"
            "2. Frente: Para que serve? | Verso: cite o objetivo pratico.\n"
            "3. Frente: Quais sao as partes? | Verso: liste 3 componentes.\n"
            "4. Frente: Qual erro comum? | Verso: descreva a confusao mais frequente.\n"
            "5. Frente: Dê um exemplo real. | Verso: aplique em um caso simples."
        )

    if _has_any(normalized, ("cronograma", "agenda de estudo")):
        topic = _topic_or_default(prompt, ("cronograma", "agenda de estudo", "estudar"), "seu tema")
        return (
            f"Cronograma de 7 dias para {topic}:\n"
            "Dia 1: visao geral e termos principais.\n"
            "Dia 2: fundamentos.\n"
            "Dia 3: exemplos praticos.\n"
            "Dia 4: exercicios.\n"
            "Dia 5: erros comuns.\n"
            "Dia 6: simulado curto.\n"
            "Dia 7: revisao e resumo final."
        )

    if "pomodoro" in normalized:
        return "Pomodoro sugerido: 25 min foco, 5 min pausa. Repita 4 vezes e faca uma pausa maior de 20 min. Antes de iniciar, defina uma tarefa unica."

    if _has_any(normalized, ("checklist de prova", "prova")):
        return "Checklist de prova: revisar resumo, resolver questoes, separar documentos, dormir bem, chegar cedo, ler comandos com calma e controlar o tempo."

    if _has_any(normalized, ("mapa mental", "mind map")):
        topic = _topic_or_default(prompt, ("mapa mental", "mind map", "sobre", "de"))
        return f"Mapa mental de {topic}: centro = tema; ramos = definicao, partes, funcionamento, exemplos, erros comuns, revisao."

    if _has_any(normalized, ("glossario", "glossário")):
        topic = _topic_or_default(prompt, ("glossario", "glossário", "de", "sobre"))
        return f"Glossario inicial de {topic}: termo, definicao curta, exemplo, comando relacionado e erro comum. Me envie a lista de termos que eu organizo."

    if _has_any(normalized, ("socratic", "socraticas")):
        topic = _topic_or_default(prompt, ("perguntas socraticas", "sobre", "de"))
        return f"Perguntas socraticas sobre {topic}: O que voce sabe? Por que isso existe? O que aconteceria se falhasse? Qual exemplo prova que voce entendeu?"

    if _has_any(normalized, ("revisao espacada", "revisao 7 dias", "revisão espaçada")):
        return "Revisao espacada: revise hoje, amanha, em 3 dias, em 7 dias, em 15 dias e em 30 dias. Em cada revisao, responda sem consultar."

    if _has_any(normalized, ("cornell", "resumo cornell")):
        topic = _topic_or_default(prompt, ("resumo cornell", "cornell", "sobre", "de"))
        return f"Resumo Cornell de {topic}:\nPistas: termos e perguntas.\nNotas: pontos principais em frases curtas.\nResumo: 5 linhas explicando o tema com suas palavras."

    if _has_any(normalized, ("roteiro de aula", "aula sobre")):
        topic = _topic_or_default(prompt, ("roteiro de aula", "aula sobre", "sobre", "de"))
        return f"Roteiro de aula sobre {topic}: objetivo, pre-requisitos, explicacao, exemplo guiado, exercicio, correcao e revisao final."

    if _has_any(normalized, ("objetivo smart", "objetivos smart", "smart")):
        topic = _topic_or_default(prompt, ("objetivos smart", "objetivo smart", "smart"), "seu objetivo")
        return f"Objetivo SMART: estudar {topic} por 30 minutos por dia, durante 7 dias, resolvendo 5 exercicios e revisando erros ao final."

    if _has_any(normalized, ("checklist de tarefa", "checklist tarefa")):
        return "Checklist de tarefa: objetivo claro, entradas necessarias, passos, criterio de pronto, teste, revisao e proxima acao."

    if _has_any(normalized, ("priorizar", "prioridade")):
        return "Priorize assim: 1. urgente e importante; 2. importante sem urgencia; 3. urgente delegavel; 4. resto. Execute uma tarefa por vez."

    if _has_any(normalized, ("rotina diaria", "rotina diária")):
        return "Rotina diaria: revisar prioridades, estudar 1 bloco, executar tarefa principal, checar sistema, registrar aprendizado e planejar amanha."

    if _has_any(normalized, ("eisenhower", "matriz")):
        return "Matriz Eisenhower: Fazer agora = urgente/importante. Agendar = importante/nao urgente. Delegar = urgente/pouco importante. Cortar = baixo valor."

    if _has_any(normalized, ("diario de aprendizado", "diário de aprendizado")):
        return "Diario de aprendizado: hoje aprendi, duvida aberta, erro cometido, exemplo pratico, proxima revisao."

    if _has_any(normalized, ("plano de projeto", "projeto passo a passo")):
        topic = _topic_or_default(prompt, ("plano de projeto", "projeto passo a passo", "projeto"), "projeto")
        return f"Plano de projeto para {topic}: objetivo, escopo, arquivos, tarefas, riscos, testes, entrega minima e melhorias futuras."

    if _has_any(normalized, ("checklist de seguranca", "checklist segurança", "seguranca do pc")):
        return "Checklist de seguranca: atualizar sistema, revisar servicos, conferir firewall, senhas fortes, backups, USBGuard, Fail2Ban, logs e integridade."

    if _has_any(normalized, ("explicar comando", "comando linux")):
        command = _payload_after_keyword(prompt, ("explicar comando linux", "explicar comando", "comando linux"))
        return f"Comando: {command or 'informe um comando'}\nComo analisar: programa, opcoes, argumentos, arquivos afetados, permissao necessaria e risco."

    if _has_any(normalized, ("nmap seguro", "comando nmap")):
        return "Nmap seguro para rede local: nmap -sn 192.168.1.0/24\nUse apenas na sua rede ou com autorizacao."

    if _has_any(normalized, ("sub-rede", "subrede", "cidr")):
        return "Guia rapido CIDR: /24 tem 256 enderecos, /25 tem 128, /26 tem 64, /27 tem 32, /28 tem 16. Hosts uteis = total menos rede e broadcast."

    if _has_any(normalized, ("portas comuns", "portas padrão", "portas padrao")):
        return "Portas comuns: 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 25 SMTP, 110 POP3, 143 IMAP, 3306 MySQL, 5432 PostgreSQL."

    if _has_any(normalized, ("analisar log", "analise de log", "análise de log")):
        return "Analise de log: procure horario, servico, severidade, usuario, origem, acao, erro exato e repeticao. Envie o trecho que eu organizo."

    if _has_any(normalized, ("explicar erro", "erro ")) and not normalized.startswith("erro de digita"):
        return "Para explicar erro, envie: mensagem completa, comando executado, arquivo afetado e o que voce esperava. Eu separo causa provavel e correcao."

    if _has_any(normalized, ("bug report", "relatorio de bug", "relatório de bug")):
        return "Bug report: titulo, ambiente, passos para reproduzir, resultado atual, resultado esperado, logs, impacto e tentativa de correcao."

    if _has_any(normalized, ("template commit", "mensagem de commit", "commit")):
        return "Template de commit: tipo(escopo): resumo curto\n\nMotivo:\n- O que mudou\n- Por que mudou\n- Como foi testado"

    if _has_any(normalized, ("regex", "expressao regular", "expressão regular")):
        return "Regex helper: diga o texto exemplo e o que quer capturar. Estrutura: ancora, grupo, classe de caracteres, quantidade e teste negativo."

    if _has_any(normalized, ("tabela markdown", "markdown tabela")):
        return _markdown_table(prompt)

    if _has_any(normalized, ("pseudocodigo", "pseudocódigo")):
        topic = _topic_or_default(prompt, ("pseudocodigo", "pseudocódigo", "de", "para"))
        return f"Pseudocodigo para {topic}: receber entrada, validar dados, processar passo principal, tratar erro, gerar saida e registrar resultado."

    if _has_any(normalized, ("checklist de codigo", "revisar codigo", "revisar código")):
        return "Checklist de codigo: legibilidade, nomes, tratamento de erro, seguranca, teste, logs, limites de entrada, performance e documentacao."

    if _has_any(normalized, ("laboratorio", "laboratório", "lab ")):
        topic = _topic_or_default(prompt, ("plano de laboratorio", "laboratorio", "laboratório", "lab"), "laboratorio")
        return f"Plano de laboratorio para {topic}: objetivo, ambiente isolado, comandos, observacoes, resultado esperado, rollback e limpeza final."

    if _has_any(normalized, ("proximos passos", "próximos passos", "o que fazer agora")):
        return "Proximos passos: defina objetivo, escolha a menor tarefa util, execute, teste, anote resultado e repita com a proxima melhoria."

    return None


def _troubleshooting_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if not _has_any(normalized, ("erro", "falha", "travando", "travado", "lento", "nao abre", "não abre", "crash")):
        return None
    topic = prompt.strip()
    return (
        f"Diagnostico rapido para: {topic}\n"
        "1. Diga exatamente o comando/app e copie a mensagem de erro completa.\n"
        "2. Rode o teste mais curto que reproduz o problema.\n"
        "3. Separe: o que mudou, quando começou, e se acontece sempre.\n"
        "4. Se for app/jogo: veja CPU, RAM, disco, GPU e temperatura no momento da travada.\n"
        "5. Proxima mensagem util: envie o erro bruto ou o log; eu separo causa provavel, correcao e teste."
    )


def _linux_helper_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if not _has_any(normalized, ("linux", "comando", "terminal", "systemctl", "journalctl", "permissao")):
        return None
    if "systemctl" in normalized:
        return (
            "Systemd rapido:\n"
            "- Ver estado: systemctl status NOME.service\n"
            "- Ver logs: journalctl -u NOME.service -n 100 --no-pager\n"
            "- Reiniciar: sudo systemctl restart NOME.service\n"
            "- Habilitar no boot: sudo systemctl enable NOME.service\n"
            "Envie o nome do servico que eu monto o comando certo."
        )
    if "journalctl" in normalized or "log" in normalized:
        return (
            "Logs rapido:\n"
            "- Ultimos logs de um servico: journalctl -u NOME.service -n 100 --no-pager\n"
            "- Logs ao vivo: journalctl -u NOME.service -f\n"
            "- Erros do boot atual: journalctl -p warning..alert -b --no-pager\n"
            "Envie o trecho do log que eu analiso."
        )
    return (
        "Para comando Linux, eu analiso assim: programa, opcoes, argumentos, arquivos afetados, permissao necessaria, risco e comando de teste. "
        "Envie o comando exato ou diga o objetivo."
    )


def _gaming_performance_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if not _has_any(normalized, ("fps", "jogo", "game", "travando", "lag", "desempenho", "performance")):
        return None
    return (
        "Checklist de FPS no Linux:\n"
        "1. Fechar overlay/stream/captura que nao precisa.\n"
        "2. Usar gamemoderun %command% na Steam.\n"
        "3. Desligar VSync, sombras, anti-aliasing, motion blur e luz volumetrica.\n"
        "4. Baixar resolucao antes de mexer em clock.\n"
        "5. Conferir se GPU esta em clock maximo e se a temperatura nao bate limite.\n"
        "6. Se ainda travar, envie jogo + resolucao + FPS alvo + top processos."
    )


def _organization_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if not _has_any(normalized, ("organiza", "bagunca", "bagunçado", "baguncado", "pratico", "checklist", "tarefas")):
        return None
    topic = prompt.strip() or "tarefa"
    return (
        f"Organizacao pratica para {topic}:\n"
        "1. Objetivo: defina o resultado final em uma frase.\n"
        "2. Agora: escolha a menor acao que desbloqueia progresso.\n"
        "3. Depois: liste no maximo 5 proximas tarefas.\n"
        "4. Teste: diga como saber que ficou pronto.\n"
        "5. Limpeza: remova duplicado, arquivo velho e comando que ninguem usa."
    )


def _study_plan_response(prompt: str) -> str | None:
    normalized = _normalize_text(prompt)
    if not any(word in normalized for word in ("estud", "plano", "aprend", "quiz", "resum", "explic", "ensina", "como funciona", "o que e")):
        return None

    if any(word in normalized for word in ("quiz", "teste", "perguntas")):
        topic = _extract_topic(prompt, [
            "faça um quiz sobre",
            "faca um quiz sobre",
            "crie um quiz sobre",
            "quiz sobre",
            "quiz de",
            "quiz",
        ])
        return (
            f"Quiz de estudo sobre {topic}:\n"
            "1. O que é o tema e para que serve?\n"
            "2. Quais são as partes ou conceitos centrais?\n"
            "3. Como isso funciona na prática?\n"
            "4. Qual erro ou confusão mais comum nesse assunto?\n"
            "5. Como você explicaria isso para outra pessoa?\n\n"
            "Gabarito de treino: responda com definição, partes, exemplo e aplicação."
        )

    if any(word in normalized for word in ("resum", "sumariz", "síntese", "sintese")):
        topic = _extract_topic(prompt, [
            "faça um resumo de",
            "faca um resumo de",
            "resuma",
            "resumir",
            "resumo de",
        ])
        return (
            f"Resumo de {topic}:\n"
            f"- Ideia central: {topic} explicado de forma direta.\n"
            "- Conceitos-chave: definição, funcionamento, aplicação e limites.\n"
            "- O que decorar: termos principais e relação entre eles.\n"
            "- O que treinar: explicar com suas próprias palavras e fazer exemplos curtos.\n"
            "- Revisão rápida: leia, responda sem olhar e corrija o que faltou."
        )

    if any(word in normalized for word in ("explic", "ensina", "como funciona", "o que e", "o que eh", "defina")):
        topic = _extract_topic(prompt, [
            "me explique",
            "explique",
            "me ensina",
            "ensina",
            "como funciona",
            "o que e",
            "o que eh",
            "defina",
            "definir",
        ])
        return (
            f"Explicação direta sobre {topic}:\n"
            f"- Definição: {topic} é o assunto central que você quer entender.\n"
            "- Como pensar: comece pelo objetivo, depois veja partes, fluxo e resultado.\n"
            "- Exemplo prático: aplique o conceito em um caso simples e repita com outro cenário.\n"
            "- Erro comum: estudar o nome do conceito sem entender a função dele.\n"
            "- Próximo passo: me peça um exercício, resumo ou quiz sobre {topic}."
        )

    if any(word in normalized for word in ("estud", "plano", "aprend", "organiza", "prepara")):
        topic = _extract_topic(prompt, [
            "me ajuda a estudar",
            "ajuda a estudar",
            "plano de estudo para",
            "monte um plano de estudo para",
            "monte um plano de estudo de",
            "quero estudar",
            "quero aprender",
            "estudar",
            "aprender",
        ])
        return (
            f"Plano de estudo para {topic}:\n"
            "1. Entenda o básico e escreva em uma frase o que o tema resolve.\n"
            "2. Separe 3 a 5 tópicos e estude um por vez.\n"
            "3. Faça 2 exemplos práticos para cada tópico.\n"
            "4. Crie 5 perguntas de revisão e responda sem consultar o material.\n"
            "5. Revise no dia seguinte e depois em 7 dias.\n\n"
            "Primeira tarefa: me diga qual parte desse tema você quer começar agora."
        )

    return None


def _pending_is_expired(item: dict[str, Any], now: int | None = None) -> bool:
    current = _now() if now is None else now
    try:
        created_at = int(item.get("created_at", 0))
        expires_at = int(item.get("expires_at", created_at + PENDING_TTL_SECONDS))
    except (TypeError, ValueError):
        return True
    return expires_at <= current


def _load_pending() -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(PENDING_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    pending = {
        str(code): item
        for code, item in data.items()
        if isinstance(item, dict) and not _pending_is_expired(item)
    }
    if len(pending) != len(data):
        try:
            _save_pending(pending)
        except OSError:
            # Expiradas continuam indisponíveis mesmo se a limpeza em disco falhar.
            pass
    return pending


def _save_pending(pending: dict[str, dict[str, Any]]) -> None:
    atomic_write_json(PENDING_FILE, pending)


def _pending_lock_path() -> Path:
    return PENDING_FILE.with_name(f".{PENDING_FILE.name}.lock")


def _pending_matches_identity(item: dict[str, Any], chat_id: str, user_id: str | None) -> bool:
    if str(item.get("chat_id")) != str(chat_id):
        return False
    bound_user_id = str(item.get("user_id", "")).strip()
    return not bound_user_id or (user_id is not None and bound_user_id == str(user_id))


def validate_pending_item(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Revalida o envelope persistido e detecta alteracao de acao/parametros."""
    if not isinstance(item, dict):
        raise PolicyViolation("pendencia invalida")
    action = item.get("action")
    payload = item.get("payload")
    if not isinstance(action, str) or not isinstance(payload, dict):
        raise PolicyViolation("pendencia sem acao ou payload valido")
    normalized_action, normalized_payload = validate_action_payload(action, payload)
    if normalized_action != action or normalized_payload != payload:
        raise PolicyViolation("pendencia nao esta em forma canonica")
    if not validate_action_digest(action, payload, item.get("action_digest", "")):
        raise PolicyViolation("digest da acao nao confere")
    return normalized_action, normalized_payload


def _load_ai_chat_history() -> dict[str, list[dict[str, str]]]:
    try:
        data = json.loads(AI_CHAT_HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}

    history: dict[str, list[dict[str, str]]] = {}
    for chat_id, messages in data.items():
        if not isinstance(messages, list):
            continue
        normalized: list[dict[str, str]] = []
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role", ""))
            content = str(message.get("content", ""))
            if role in {"user", "assistant"} and content:
                normalized.append({"role": role, "content": content[:AI_CHAT_MESSAGE_MAX_CHARS]})
        if normalized:
            history[str(chat_id)] = normalized[-AI_CHAT_HISTORY_MESSAGES:]
    return history


def _save_ai_chat_history(history: dict[str, list[dict[str, str]]]) -> None:
    atomic_write_json(AI_CHAT_HISTORY_FILE, history)


def _load_ai_memory() -> list[dict[str, str]]:
    try:
        data = json.loads(AI_MEMORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    memory: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        content = str(item.get("content", "")).strip()
        if not content:
            continue
        memory.append(
            {
                "created_at": str(item.get("created_at", "")),
                "kind": str(item.get("kind", "note")),
                "title": str(item.get("title", "Memoria")),
                "source": str(item.get("source", "")),
                "content": content[:AI_MEMORY_ITEM_MAX_CHARS],
                "trusted": bool(item.get("trusted", False)),
            }
        )
    return memory[-AI_MEMORY_MAX_ITEMS:]


def _save_ai_memory(memory: list[dict[str, str]]) -> None:
    atomic_write_json(AI_MEMORY_FILE, memory[-AI_MEMORY_MAX_ITEMS:])


def add_ai_memory(
    kind: str,
    title: str,
    content: str,
    source: str = "",
    *,
    trusted: bool = False,
) -> int:
    memory = _load_ai_memory()
    item = {
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "kind": kind[:40],
        "title": title.strip()[:160] or "Memoria",
        "source": source.strip()[:240],
        "content": content.strip()[:AI_MEMORY_ITEM_MAX_CHARS],
        "trusted": bool(trusted),
    }
    memory.append(item)
    _save_ai_memory(memory)
    return len(memory[-AI_MEMORY_MAX_ITEMS:])


def clear_ai_memory() -> None:
    _save_ai_memory([])


def search_ai_memory(query: str, limit: int = 8) -> list[dict[str, str]]:
    normalized_terms = [term for term in _normalize_text(query).split() if len(term) >= 3]
    memory = _load_ai_memory()
    if not normalized_terms:
        return memory[-limit:]

    scored: list[tuple[int, dict[str, str]]] = []
    for item in memory:
        haystack = _normalize_text(" ".join([item.get("title", ""), item.get("source", ""), item.get("content", "")]))
        score = sum(haystack.count(term) for term in normalized_terms)
        if score:
            scored.append((score, item))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [item for _score, item in scored[:limit]]


def format_ai_memory(items: list[dict[str, str]]) -> str:
    if not items:
        return "A memoria da Voz ainda esta vazia."
    lines = ["Memoria da Voz:"]
    for index, item in enumerate(items, start=1):
        title = item.get("title", "Memoria")
        kind = item.get("kind", "note")
        source = item.get("source", "")
        excerpt = item.get("content", "").replace("\n", " ")[:220]
        source_text = f" · {source}" if source else ""
        lines.append(f"{index}. [{kind}] {title}{source_text}\n   {excerpt}")
    return "\n".join(lines)


def memory_context(query: str = "", max_chars: int = 1800) -> str:
    items = search_ai_memory(query, limit=8) if query.strip() else _load_ai_memory()[-8:]
    items = [item for item in items if bool(item.get("trusted", False))]
    if query.strip() and not items:
        items = _load_ai_memory()[-4:]
    if not items:
        return ""
    parts = []
    for item in items:
        parts.append(f"- {item.get('title', 'Memoria')}: {item.get('content', '')[:300]}")
    return "\n".join(parts)[-max_chars:]


def remember_ai_chat(chat_id: str | None, prompt: str, response: str) -> None:
    if not chat_id:
        return
    history = _load_ai_chat_history()
    messages = history.get(str(chat_id), [])
    messages.extend(
        [
            {"role": "user", "content": prompt.strip()[:AI_CHAT_MESSAGE_MAX_CHARS]},
            {"role": "assistant", "content": response.strip()[:AI_CHAT_MESSAGE_MAX_CHARS]},
        ]
    )
    history[str(chat_id)] = messages[-AI_CHAT_HISTORY_MESSAGES:]
    _save_ai_chat_history(history)


def clear_ai_chat_history(chat_id: str) -> None:
    history = _load_ai_chat_history()
    history.pop(str(chat_id), None)
    _save_ai_chat_history(history)


def append_remote_log(event: str, **fields: Any) -> None:
    REMOTE_LOG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {"timestamp": _now(), "event": event, **fields}
    with REMOTE_LOG.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
    os.chmod(REMOTE_LOG, 0o600)
    record_event(f"remote_{event}", **fields)


def create_pending(
    chat_id: str,
    action: str,
    payload: dict[str, Any],
    description: str,
    *,
    user_id: str | None = None,
) -> str:
    ensure_remote_action_enabled(action)
    normalized_action, normalized_payload = validate_action_payload(action, payload)
    if normalized_action == "shell":
        validate_shell_command(normalized_payload["command"])
    if normalized_action == "install_package":
        description = f"{description}\n\n{package_install_preview(normalized_payload['package'])}"
    created_at = _now()
    with exclusive_file_lock(_pending_lock_path()):
        pending = _load_pending()
        code = secrets.token_hex(16).upper()
        while code in pending:
            code = secrets.token_hex(16).upper()
        item = {
            "chat_id": str(chat_id),
            "action": normalized_action,
            "payload": normalized_payload,
            "action_digest": canonical_action_digest(normalized_action, normalized_payload),
            "description": str(description)[:2000],
            "created_at": created_at,
            "expires_at": created_at + PENDING_TTL_SECONDS,
        }
        if user_id is not None and str(user_id).strip():
            item["user_id"] = str(user_id)
        pending[code] = item
        _save_pending(pending)
    append_remote_log(
        "pending_created",
        chat_id=str(chat_id),
        user_id=str(user_id) if user_id is not None else "",
        code_sha256=hashlib.sha256(code.encode("ascii")).hexdigest(),
        action=normalized_action,
        action_digest=item["action_digest"],
    )
    return code


def pop_pending(chat_id: str, code: str, *, user_id: str | None = None) -> dict[str, Any] | None:
    normalized = code.strip().upper()
    rejected_reason = ""
    with exclusive_file_lock(_pending_lock_path()):
        pending = _load_pending()
        item = pending.get(normalized)
        if not item or _pending_is_expired(item) or not _pending_matches_identity(item, chat_id, user_id):
            return None
        try:
            validate_pending_item(item)
        except PolicyViolation as exc:
            rejected_reason = str(exc)
        pending.pop(normalized, None)
        _save_pending(pending)
    if rejected_reason:
        append_remote_log(
            "pending_rejected",
            chat_id=str(chat_id),
            code_sha256=hashlib.sha256(normalized.encode("ascii", errors="ignore")).hexdigest(),
            reason=rejected_reason,
        )
        return None
    return item


def list_pending(chat_id: str, *, user_id: str | None = None) -> list[tuple[str, dict[str, Any]]]:
    with exclusive_file_lock(_pending_lock_path()):
        pending = _load_pending()
        valid: list[tuple[str, dict[str, Any]]] = []
        invalid_codes: list[str] = []
        for code, item in sorted(pending.items()):
            try:
                validate_pending_item(item)
            except PolicyViolation:
                invalid_codes.append(code)
                continue
            if _pending_matches_identity(item, chat_id, user_id):
                valid.append((code, item))
        if invalid_codes:
            for code in invalid_codes:
                pending.pop(code, None)
            _save_pending(pending)
        return valid


def cancel_pending(chat_id: str, code: str, *, user_id: str | None = None) -> bool:
    normalized = code.strip().upper()
    with exclusive_file_lock(_pending_lock_path()):
        pending = _load_pending()
        item = pending.get(normalized)
        if not item or _pending_is_expired(item) or not _pending_matches_identity(item, chat_id, user_id):
            return False
        try:
            validate_pending_item(item)
        except PolicyViolation:
            pending.pop(normalized, None)
            _save_pending(pending)
            return False
        pending.pop(normalized, None)
        _save_pending(pending)
    append_remote_log(
        "pending_cancelled",
        chat_id=str(chat_id),
        code_sha256=hashlib.sha256(normalized.encode("ascii", errors="ignore")).hexdigest(),
        action=item.get("action"),
    )
    return True


def _bunkerctl_argv(operation: str) -> list[str]:
    for candidate in (Path("/usr/local/bin/bunkerctl"), Path("/usr/bin/bunkerctl")):
        if candidate.is_file():
            return [str(candidate), operation]
    local_controller = Path(__file__).resolve().with_name("bunkerctl.py")
    if not local_controller.is_file():
        raise PolicyViolation("bunkerctl nao encontrado em caminho confiavel")
    return [sys.executable, str(local_controller), operation]


def _systemctl_executable() -> str:
    for candidate in (Path("/usr/bin/systemctl"), Path("/bin/systemctl")):
        if candidate.is_file():
            return str(candidate)
    raise PolicyViolation("systemctl nao encontrado em caminho absoluto confiavel")


def execute_typed_action(
    action: str,
    payload: dict[str, Any],
    timeout: int | None = None,
) -> tuple[int, str]:
    """Executa somente operacoes internas tipadas, sempre sem interpretador shell."""
    normalized_action, normalized_payload = validate_action_payload(action, payload)
    if normalized_action == "service":
        service_code = normalized_payload["service_code"]
        unit = REMOTE_SERVICE_UNITS.get(service_code)
        if not unit:
            raise PolicyViolation(f"servico {service_code} pertence a outro controlador")
        argv = [_systemctl_executable(), normalized_payload["service_action"], unit]
    elif normalized_action == "bunker_services":
        argv = _bunkerctl_argv(normalized_payload["operation"])
    else:
        raise PolicyViolation(f"acao nao possui executor tipado: {normalized_action}")

    started = time.time()
    try:
        result = subprocess.run(
            argv,
            shell=False,
            cwd=str(HOME),
            capture_output=True,
            text=True,
            timeout=timeout or DEFAULT_TIMEOUT,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        status = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = f"Acao excedeu timeout de {timeout or DEFAULT_TIMEOUT}s.\n{exc.stdout or ''}\n{exc.stderr or ''}"
        status = 124
    except OSError as exc:
        output = f"Falha ao iniciar executor tipado: {exc}"
        status = 127
    append_remote_log(
        "typed_action_executed",
        action=normalized_action,
        action_digest=canonical_action_digest(normalized_action, normalized_payload),
        executable=Path(argv[0]).name,
        returncode=status,
        elapsed_ms=int((time.time() - started) * 1000),
    )
    return status, truncate_output(output.strip() or "(sem saída)")


def execute_shell(command: str, timeout: int | None = None) -> tuple[int, str]:
    try:
        ensure_remote_action_enabled("shell")
    except RemoteFeatureDisabled as exc:
        return 126, str(exc)

    try:
        argv = validate_shell_command(command)
    except ValueError as exc:
        return 126, str(exc)

    started = time.time()
    try:
        result = subprocess.run(
            argv,
            shell=False,
            cwd=str(HOME),
            capture_output=True,
            text=True,
            timeout=timeout or DEFAULT_TIMEOUT,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        status = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = f"Comando excedeu timeout de {timeout or DEFAULT_TIMEOUT}s.\n{exc.stdout or ''}\n{exc.stderr or ''}"
        status = 124
    elapsed_ms = int((time.time() - started) * 1000)
    command_hash, executable = shell_audit_metadata(command)
    append_remote_log(
        "shell_executed",
        command_sha256=command_hash,
        executable=executable,
        returncode=status,
        elapsed_ms=elapsed_ms,
    )
    return status, truncate_output(output.strip() or "(sem saída)")


def validate_shell_command(command: str) -> list[str]:
    """Transforma um comando simples em argv e bloqueia sintaxe de shell."""
    normalized = command.strip()
    if not normalized or len(normalized) > 8192:
        raise ValueError("Comando vazio ou grande demais.")
    if SHELL_FORBIDDEN_RE.search(normalized):
        raise ValueError("Comando bloqueado: operadores, substituições ou caracteres de controle não são permitidos.")
    try:
        argv = shlex.split(normalized, posix=True)
    except ValueError as exc:
        raise ValueError(f"Comando inválido: {exc}") from exc
    if not argv or argv[0].startswith("-"):
        raise ValueError("Executável inválido.")
    return argv


def shell_audit_metadata(command: str) -> tuple[str, str]:
    digest = hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()
    executable = "shell"
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = []
    for token in tokens:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token, re.DOTALL):
            continue
        candidate = Path(token).name
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", candidate):
            executable = candidate
        break
    return digest, executable


def truncate_output(output: str) -> str:
    if len(output) <= MAX_OUTPUT_CHARS:
        return output
    omitted = len(output) - MAX_OUTPUT_CHARS
    return output[:MAX_OUTPUT_CHARS] + f"\n\n...[{omitted} caracteres omitidos]"


def resolve_path(raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = HOME / path
    return path.resolve()


def _looks_like_path(raw_path: str) -> bool:
    cleaned = raw_path.strip()
    return bool(cleaned) and ("/" in cleaned or "\\" in cleaned or "." in Path(cleaned).name or cleaned.startswith("~"))


def extract_send_path_request(prompt: str) -> str | None:
    match = SEND_PATH_PHRASE_RE.match(prompt.strip())
    if not match:
        return None

    kind = (match.group("kind") or "").lower()
    raw_path = match.group("path").strip(" \t\r\n\"'`")
    raw_path = re.sub(r"\s+(?:por favor|pra mim|para mim)$", "", raw_path, flags=re.IGNORECASE).strip(" \t\r\n\"'`")
    if not raw_path:
        return None
    if kind in {"arquivo", "pasta", "documento", "pdf"} or _looks_like_path(raw_path):
        return raw_path
    return None


def extract_terminal_command_request(prompt: str) -> str | None:
    normalized = _normalize_text(prompt).strip()
    for prefix in ("terminal", "cmd", "comando", "executar", "codigo", "code"):
        if normalized.startswith(f"{prefix}:") or normalized.startswith(f"{prefix} "):
            command = prompt[len(prefix):].lstrip(" :\t\r\n")
            return command.strip() or None

    block = CODE_BLOCK_RE.match(prompt.strip())
    if not block:
        return None

    lang = _normalize_text(block.group("lang")).strip()
    body = block.group("body").strip()
    if not body:
        return None

    if lang in {"bash", "sh", "shell", "zsh", "fish", "cmd", "console", "terminal"}:
        return body
    if lang in {"python", "py", "python3"}:
        return f"python3 - <<'PY'\n{body}\nPY"
    if lang in {"perl"}:
        return f"perl - <<'PL'\n{body}\nPL"
    if lang in {"ruby", "rb"}:
        return f"ruby - <<'RB'\n{body}\nRB"
    return body


def export_allowed_roots() -> list[Path]:
    roots: list[Path] = []
    seen: set[str] = set()
    for configured in REMOTE_EXPORT_ALLOWED_ROOTS.split(","):
        raw = os.path.expandvars(configured.strip())
        if not raw:
            continue
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = HOME / path
        path = path.resolve()
        if path == Path("/"):
            continue
        key = str(path)
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        roots.append(path)
    return roots


def _path_within_root(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def export_path_allowed(path: Path) -> bool:
    resolved = path.resolve()
    return any(_path_within_root(resolved, root) for root in export_allowed_roots())


def sensitive_export_path(path: Path) -> bool:
    lowered_parts = [part.casefold() for part in path.parts]
    if any(part in SENSITIVE_EXPORT_PARTS for part in lowered_parts):
        return True
    name = path.name.casefold()
    if name == ".env" or name.startswith(".env."):
        return True
    if name in SENSITIVE_EXPORT_NAMES or name.endswith(SENSITIVE_EXPORT_SUFFIXES):
        return True
    return bool(SENSITIVE_EXPORT_WORD_RE.search(name))


def export_tree_is_sensitive(path: Path) -> bool:
    if sensitive_export_path(path):
        return True
    if not path.is_dir():
        return False
    try:
        return any(sensitive_export_path(item) for item in path.rglob("*"))
    except OSError:
        return True


def find_send_candidate(raw_path: str, max_scanned: int = 200000) -> Path | None:
    cleaned = raw_path.strip().strip("\"'`")
    if not cleaned or "/" in cleaned or "\\" in cleaned:
        return None

    target_name = Path(cleaned).name
    if not target_name or target_name in {".", ".."}:
        return None

    search_roots = export_allowed_roots()
    for directory in search_roots:
        direct = directory / target_name
        if direct.exists() and export_path_allowed(direct) and not export_tree_is_sensitive(direct):
            return direct.resolve()

    target_lower = target_name.casefold()
    scanned = 0
    for directory in search_roots:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [name for name in dirs if not sensitive_export_path(Path(root) / name)]
            scanned += len(dirs) + len(files)
            entries = dirs + files
            for entry in entries:
                if entry.casefold() != target_lower:
                    continue
                candidate = (Path(root) / entry).resolve()
                if export_path_allowed(candidate) and not export_tree_is_sensitive(candidate):
                    return candidate
            if scanned >= max_scanned:
                return None
    return None


def path_exceeds_size(path: Path, limit_bytes: int) -> bool:
    total = 0
    if path.is_file():
        return path.stat().st_size > limit_bytes

    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
        if total > limit_bytes:
            return True
    return False


def archive_for_send(raw_path: str) -> tuple[Path | None, str]:
    try:
        ensure_remote_action_enabled("send_path")
    except RemoteFeatureDisabled as exc:
        return None, str(exc)

    if not export_allowed_roots():
        return None, "Exportação remota sem raízes permitidas. Configure REMOTE_EXPORT_ALLOWED_ROOTS localmente."

    path = resolve_path(raw_path)
    if not path.exists():
        candidate = find_send_candidate(raw_path)
        if candidate is None:
            return None, "Arquivo não encontrado nas raízes permitidas."
        path = candidate

    if not export_path_allowed(path):
        return None, "Caminho fora das raízes permitidas para exportação."
    if export_tree_is_sensitive(path):
        return None, "Exportação recusada: o caminho contém configuração, credencial ou token sensível."

    limit_bytes = MAX_UPLOAD_MB * 1024 * 1024
    if path.is_file():
        if path.stat().st_size > limit_bytes:
            return None, f"Arquivo maior que {MAX_UPLOAD_MB} MB: {path}"
        return path, f"Arquivo pronto: {path}"

    if not path.is_dir():
        return None, f"Caminho não é arquivo nem pasta: {path}"

    if path_exceeds_size(path, limit_bytes):
        return None, (
            f"Pasta maior que {MAX_UPLOAD_MB} MB antes de compactar: {path}. "
            "Envie uma subpasta ou arquivo menor."
        )

    target_dir = Path(tempfile.gettempdir()) / "kali-bunker-telegram"
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target_dir, 0o700)
    archive = target_dir / f"{EXPORT_ARCHIVE_PREFIX}{secrets.token_hex(16)}.tar.gz"
    try:
        with tarfile.open(archive, "x:gz") as tar:
            tar.add(path, arcname=path.name)
        os.chmod(archive, 0o600)
    except (OSError, tarfile.TarError):
        archive.unlink(missing_ok=True)
        return None, "Falha ao compactar a pasta para exportação."
    size_mb = archive.stat().st_size / 1024 / 1024
    if size_mb > MAX_UPLOAD_MB:
        archive.unlink(missing_ok=True)
        return None, f"Pasta compactada ficou com {size_mb:.1f} MB; limite atual {MAX_UPLOAD_MB} MB."
    return archive, f"Pasta compactada: {archive.name} ({size_mb:.1f} MB)"


def cleanup_export_artifact(path: Path) -> None:
    if path.name.startswith(EXPORT_ARCHIVE_PREFIX) and path.parent == Path(tempfile.gettempdir()) / "kali-bunker-telegram":
        path.unlink(missing_ok=True)


def ai_available() -> bool:
    global OPENAI_AUTH_DISABLED
    if not OPENAI_API_KEY:
        return False
    if OPENAI_AUTH_DISABLED and _OPENAI_AUTH_DISABLED_AT > 0:
        if time.time() - _OPENAI_AUTH_DISABLED_AT >= _OPENAI_AUTH_COOLDOWN:
            OPENAI_AUTH_DISABLED = False
            print("[IA] Cooldown expirado, reativando acesso à API OpenAI.")
    return not OPENAI_AUTH_DISABLED


def gemini_available() -> bool:
    return bool(GEMINI_API_KEY)


def ai_provider_order() -> list[str]:
    """Ordena provedores configurados sem deixar uma API sem cota degradar o chat."""
    if AI_PROVIDER == "openai":
        requested = ("openai", "gemini")
    elif AI_PROVIDER == "gemini":
        requested = ("gemini", "openai")
    else:
        requested = ("gemini", "openai") if gemini_available() else ("openai",)
    return [
        provider
        for provider in requested
        if (provider == "gemini" and gemini_available())
        or (provider == "openai" and ai_available())
    ]


def active_ai_description() -> str:
    providers = ai_provider_order()
    if providers and providers[0] == "gemini":
        return f"Gemini ({GEMINI_MODEL})"
    if providers and providers[0] == "openai":
        return f"OpenAI ({AI_MODEL})"
    return "modo local, porque nenhuma API de IA está disponível"


def openai_response(payload: dict[str, Any]) -> dict[str, Any]:
    global OPENAI_AUTH_DISABLED, _OPENAI_AUTH_DISABLED_AT
    last_error: requests.RequestException | None = None
    api_payload = dict(payload)
    if "messages" not in api_payload and "input" in api_payload:
        api_payload["messages"] = api_payload.pop("input")
    for attempt in range(3):
        try:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
                json=api_payload,
                timeout=OPENAI_TIMEOUT_SECONDS,
            )
            if response.status_code in {401, 403}:
                OPENAI_AUTH_DISABLED = True
                _OPENAI_AUTH_DISABLED_AT = time.time()
            response.raise_for_status()
            return response.json()
        except requests.ConnectionError as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
        except requests.RequestException:
            raise
    raise last_error


def gemini_response(system_prompt: str, messages: list[dict[str, str]], model: str) -> str:
    contents: list[dict[str, Any]] = []
    for message in messages:
        role = message.get("role", "user")
        if role == "system":
            continue
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": message.get("content", "")} ]})

    payload = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {
            "temperature": 0.45,
            "maxOutputTokens": max(AI_MAX_OUTPUT_TOKENS, 1600),
            "responseMimeType": "application/json",
        },
    }
    response = requests.post(
        GEMINI_API_URL.format(model=model),
        headers={"x-goog-api-key": GEMINI_API_KEY, "Content-Type": "application/json"},
        json=payload,
        timeout=OPENAI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    try:
        parts = data["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("Gemini não retornou conteúdo utilizável.") from exc
    text = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict)).strip()
    if not text:
        raise ValueError("Gemini retornou uma resposta vazia.")
    return text


def fallback_plan(prompt: str) -> dict[str, str] | None:
    lowered = prompt.lower()
    normalized = _normalize_text(prompt)
    command = extract_terminal_command_request(prompt)
    if command:
        return {"action": "shell", "command": command, "explanation": "Executar comando informado via fallback local."}
    if _is_status_request(normalized):
        return {"action": "status", "explanation": "Mostrar status resumido do Kali Bunker."}
    if any(
        phrase in normalized
        for phrase in (
            "apague todas as mensagens do bot",
            "apagar todas as mensagens do bot",
            "limpe todas as mensagens do bot",
            "limpar todas as mensagens do bot",
            "apagar mensagens do bot",
            "limpar mensagens do bot",
            "delete bot messages",
            "delete all bot messages",
        )
    ):
        return {"action": "purge_bot_messages", "explanation": "Apagar as mensagens do bot neste chat."}
    natural_path = extract_send_path_request(prompt)
    if natural_path:
        return {"action": "send_path", "path": natural_path, "explanation": "Enviar arquivo ou pasta solicitado."}
    for prefix in ("arquivo", "pasta", "enviar"):
        if lowered.startswith(f"{prefix}:") or lowered.startswith(f"{prefix} "):
            path = prompt[len(prefix):].lstrip(" :")
            return {"action": "send_path", "path": path, "explanation": "Enviar caminho informado via fallback local."}
    if any(word in lowered for word in ("foto", "selfie", "webcam", "camera")):
        return {"action": "webcam", "explanation": "Capturar foto da webcam integrada do notebook."}
    install_match = INSTALL_TRIGGER_RE.match(prompt.strip())
    if install_match:
        package = install_match.group("package").strip().strip("`'\"")
        package = re.sub(r"^(?:o|a|os|as|um|uma|pacote|pacotes)\s+", "", package, flags=re.IGNORECASE)
        if PACKAGE_NAME_RE.match(package):
            return {
                "action": "install_package",
                "package": package,
                "explanation": f"Instalar pacote {package}.",
            }
    for keyword, service_code in SERVICE_KEYWORDS.items():
        if keyword in lowered and any(verb in lowered for verb in ("reinicia", "reiniciar", "restart", "start", "para", "parar", "stop")):
            service_action = "restart"
            if re.search(r"\b(?:inicia|iniciar|start)\b", lowered):
                service_action = "start"
            elif re.search(r"\b(?:para|parar|stop)\b", lowered):
                service_action = "stop"
            return {
                "action": "service",
                "service_action": service_action,
                "service_code": service_code,
                "explanation": f"{service_action} do serviço {service_code}.",
            }
    scan_words = ("nmap", "scan", "escan", "mapear", "listar", "descobrir", "procurar")
    network_words = ("rede", "network", "wifi", "wi-fi", "dispositivo", "host", "ips")
    if any(word in lowered for word in scan_words) and any(word in lowered for word in network_words):
        return {
            "action": "network_scan",
            "explanation": "Escanear a rede local conectada com o scanner seguro do Kali Bunker.",
        }
    return None


def _is_status_request(normalized: str) -> bool:
    status_words = ("status", "saude", "saúde", "resumo")
    system_words = ("pc", "sistema", "bunker", "maquina", "máquina", "computador", "defesa", "protec")
    return any(word in normalized for word in status_words) and any(word in normalized for word in system_words)


def _safe_eval_expression(expression: str) -> str | None:
    operators = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.Mod: lambda a, b: a % b,
        ast.Pow: lambda a, b: a**b,
    }

    def walk(node: ast.AST) -> float | int:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -walk(node.operand)
        if isinstance(node, ast.BinOp) and type(node.op) in operators:
            left = walk(node.left)
            right = walk(node.right)
            return operators[type(node.op)](left, right)
        raise ValueError("Expressão inválida")

    try:
        tree = ast.parse(expression, mode="eval")
        result = walk(tree)
    except Exception:
        return None
    if isinstance(result, float) and result.is_integer():
        result = int(result)
    return str(result)


def local_chat_response(prompt: str, chat_id: str | None = None) -> str:
    lowered = prompt.strip().lower()
    normalized = _normalize_text(prompt)
    if not lowered:
        return "Diga o que você quer fazer. Sou a Voz: posso estudar com você, lembrar informações, analisar arquivos e preparar ações do PC com confirmação."
    if normalized.startswith(("lembre que ", "memorize ", "guarde na memoria ", "guarde na memória ")):
        content = re.sub(r"^(lembre que|memorize|guarde na memoria|guarde na memória)\s+", "", prompt.strip(), flags=re.IGNORECASE)
        if not content.strip():
            return "Me diga o que devo guardar na memoria."
        count = add_ai_memory("note", "Ensinado pelo usuario", content, source="user:telegram", trusted=True)
        return f"Memoria salva na Voz. Agora tenho {count} item(ns) na memoria local."
    if any(phrase in normalized for phrase in ("o que voce lembra", "o que vc lembra", "ver memoria", "mostrar memoria", "minha memoria")):
        return format_ai_memory(_load_ai_memory()[-12:])
    if normalized.startswith(("procure na memoria", "pesquise na memoria", "buscar memoria")):
        query = _payload_after_keyword(prompt, ("procure na memoria", "pesquise na memoria", "buscar memoria"))
        return format_ai_memory(search_ai_memory(query))
    if any(phrase in normalized for phrase in ("limpar memoria da voz", "apagar memoria da voz", "zerar memoria da voz")):
        clear_ai_memory()
        return "Memoria permanente da Voz apagada."
    if any(
        phrase in normalized
        for phrase in (
            "limpe as conversas voz",
            "limpar as conversas voz",
            "limpar conversas voz",
            "apagar conversas voz",
            "zerar conversas voz",
            "limpe a conversa voz",
            "limpar conversa voz",
            "apagar conversa voz",
            "zerar conversa voz",
            "limpar conversa",
            "apagar conversa",
        )
    ):
        if chat_id:
            clear_ai_chat_history(chat_id)
        return "Conversa curta da Voz limpa."
    utility = utility_response(prompt)
    if utility:
        return utility
    for local_helper in (
        _gaming_performance_response,
        _troubleshooting_response,
        _linux_helper_response,
        _organization_response,
    ):
        response = local_helper(prompt)
        if response:
            return response
    if any(phrase in lowered for phrase in ("como vc esta", "como você está", "como voce esta", "tudo bem")):
        return "Estou bem e funcionando. E você? O que vamos resolver agora?"
    if _is_greeting(normalized):
        return "Oi! O que você quer resolver agora?"
    if any(
        phrase in lowered
        for phrase in (
            "que dia",
            "qual a data",
            "qual o dia",
            "hoje é que dia",
            "que dia é hoje",
            "que dia é hj",
            "que dia eh hj",
            "data de hoje",
            "dia de hoje",
        )
    ):
        weekdays = [
            "segunda-feira",
            "terça-feira",
            "quarta-feira",
            "quinta-feira",
            "sexta-feira",
            "sábado",
            "domingo",
        ]
        months = [
            "janeiro",
            "fevereiro",
            "março",
            "abril",
            "maio",
            "junho",
            "julho",
            "agosto",
            "setembro",
            "outubro",
            "novembro",
            "dezembro",
        ]
        now = datetime.now()
        return f"Hoje é {weekdays[now.weekday()]}, {now.day} de {months[now.month - 1]} de {now.year}."
    if any(word in lowered for word in ("quem é você", "quem e voce", "quem é voce", "quem e você")):
        return "Sou a Voz, sua assistente local do Kali Bunker. Eu converso, estudo com você, guardo memoria local e preparo ações com confirmação."
    if any(
        phrase in normalized
        for phrase in (
            "qual seu modelo",
            "qual o seu modelo",
            "qual modelo de ia",
            "que modelo de ia",
            "qual ia voce usa",
            "qual ia vc usa",
            "voce usa qual ia",
        )
    ):
        return f"No momento, minha IA principal é {active_ai_description()}. Eu sou a Voz, a assistente do Kali Bunker."
    study_response = _study_plan_response(prompt)
    if study_response:
        return study_response
    match = ARITHMETIC_RE.search(prompt.replace("x", "*").replace("÷", "/"))
    if match:
        result = _safe_eval_expression(match.group(0))
        if result is not None:
            return result
    if "nmap" in lowered:
        return "Posso preparar um nmap da rede ou montar um scan mais específico."
    if any(word in lowered for word in ("foto", "selfie", "webcam", "camera")):
        return "Posso capturar a webcam integrada do notebook."
    if any(word in lowered for word in ("arquivo", "pasta", "enviar")):
        return "Posso preparar envio de arquivo ou pasta. Diga o caminho exato."
    if any(word in lowered for word in ("status", "saude", "saúde")):
        return "Posso mostrar o status do sistema e das proteções."
    if any(word in lowered for word in ("instalar", "instale", "instala", "install", "baixar", "baixe", "download")):
        return "Posso instalar pacotes específicos com confirmação."
    return (
        "Não consegui acessar a IA online para responder bem a essa mensagem. "
        "Prefiro ser transparente a devolver uma resposta genérica; tente novamente em alguns instantes."
    )


def fast_local_chat_response(prompt: str, chat_id: str | None = None) -> str | None:
    if not AI_FAST_LOCAL_RESPONSES:
        return None
    stripped = prompt.strip()
    normalized = _normalize_text(stripped)
    lowered = stripped.lower()
    if not stripped:
        return local_chat_response(prompt, chat_id)
    if normalized.startswith(("lembre que ", "memorize ", "guarde na memoria ", "guarde na memória ")):
        return local_chat_response(prompt, chat_id)
    if normalized.startswith(("procure na memoria", "pesquise na memoria", "buscar memoria")):
        return local_chat_response(prompt, chat_id)
    if any(
        phrase in normalized
        for phrase in (
            "o que voce lembra",
            "o que vc lembra",
            "ver memoria",
            "mostrar memoria",
            "minha memoria",
            "limpar memoria da voz",
            "apagar memoria da voz",
            "zerar memoria da voz",
            "limpar conversa",
            "apagar conversa",
        )
    ):
        return local_chat_response(prompt, chat_id)
    utility = utility_response(prompt)
    if utility:
        return utility
    for local_helper in (
        _gaming_performance_response,
        _troubleshooting_response,
        _linux_helper_response,
        _organization_response,
    ):
        response = local_helper(prompt)
        if response:
            return response
    if any(phrase in lowered for phrase in ("como vc esta", "como você está", "como voce esta", "tudo bem")):
        return local_chat_response(prompt, chat_id)
    if _is_greeting(normalized):
        return local_chat_response(prompt, chat_id)
    if any(
        phrase in lowered
        for phrase in (
            "que dia",
            "qual a data",
            "qual o dia",
            "hoje é que dia",
            "que dia é hoje",
            "que dia é hj",
            "que dia eh hj",
            "data de hoje",
            "dia de hoje",
        )
    ):
        return local_chat_response(prompt, chat_id)
    if any(word in lowered for word in ("quem é você", "quem e voce", "quem é voce", "quem e você")):
        return local_chat_response(prompt, chat_id)
    match = ARITHMETIC_RE.search(prompt.replace("x", "*").replace("÷", "/"))
    if match:
        result = _safe_eval_expression(match.group(0))
        if result is not None:
            return result
    return None


def _trim_ai_messages(messages: list[dict[str, str]], max_chars: int) -> list[dict[str, str]]:
    if max_chars <= 0 or not messages:
        return messages
    if len(messages) <= 2:
        return messages

    system_message = messages[0]
    user_message = messages[-1]
    base_chars = len(system_message.get("content", "")) + len(user_message.get("content", ""))
    remaining = max_chars - base_chars
    if remaining <= 0:
        return [system_message, user_message]

    kept: list[dict[str, str]] = []
    for message in reversed(messages[1:-1]):
        content = message.get("content", "")
        size = len(content)
        if size <= remaining:
            kept.append(message)
            remaining -= size
            continue
        if remaining >= 300:
            kept.append({"role": message.get("role", "user"), "content": content[-remaining:]})
        break
    return [system_message, *reversed(kept), user_message]


def install_package(package: str) -> tuple[bool, str]:
    try:
        ensure_remote_action_enabled("install_package")
    except RemoteFeatureDisabled as exc:
        return False, str(exc)

    normalized = package.strip().strip("`'\"")
    if not normalized or not PACKAGE_NAME_RE.fullmatch(normalized):
        return False, "Nome do pacote inválido."
    preview = package_install_preview(normalized)
    dry_run = ["apt-get", "install", "--dry-run", "--no-remove", "--", normalized]
    try:
        dry_result = subprocess.run(dry_run, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{preview}\n\nFalha na simulação do APT: {exc}"
    if dry_result.returncode != 0:
        detail = (dry_result.stderr or dry_result.stdout).strip() or "simulação do APT falhou"
        return False, f"{preview}\n\n{detail[-1200:]}"
    command = ["sudo", "-n", "apt-get", "install", "--yes", "--no-remove", "--", normalized]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode == 0:
        return True, f"Pacote instalado: {normalized}\n{preview}"
    detail = (result.stderr or result.stdout).strip() or f"codigo {result.returncode}"
    return False, detail[-1200:]


def package_install_preview(package: str) -> str:
    """Mostra identidade do pacote antes da confirmação remota."""
    normalized = package.strip().strip("`'\"")
    if not PACKAGE_NAME_RE.fullmatch(normalized):
        raise ValueError("Nome do pacote inválido.")
    try:
        result = subprocess.run(
            ["apt-cache", "show", "--no-all-versions", "--", normalized],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"Pacote solicitado: {normalized}\nMetadados indisponíveis: {exc}"
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key in {"Package", "Version", "Maintainer", "Origin"} and key not in fields:
            fields[key] = value.strip()
    if not fields:
        return f"Pacote solicitado: {normalized}\nMetadados não encontrados no APT."
    return "Pacote APT confirmado:\n" + "\n".join(f"{key}: {fields[key]}" for key in ("Package", "Version", "Maintainer", "Origin") if key in fields)


def fallback_chat_response(prompt: str, chat_id: str | None = None) -> str:
    return local_chat_response(prompt, chat_id)


def response_text(data: dict[str, Any]) -> str:
    text = data.get("output_text")
    if text:
        return str(text).strip()

    output = data.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") in {"output_text", "text"} and block.get("text"):
                    return str(block["text"]).strip()

    try:
        return str(data["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError, TypeError):
        return ""


def json_object_from_response(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        payload = json.loads(cleaned[start : end + 1])

    if not isinstance(payload, dict):
        raise ValueError("Resposta JSON não é um objeto.")
    return payload


def ai_assistant(prompt: str, chat_id: str | None = None) -> dict[str, str]:
    fallback = fallback_plan(prompt)
    if fallback:
        if fallback.get("action") in {"shell", "send_path", "status", "webcam", "install_package", "service", "purge_bot_messages", "network_scan"}:
            return fallback
        return {"action": "chat", "response": fallback_chat_response(prompt, chat_id), "explanation": "Resposta local."}

    local_response = fast_local_chat_response(prompt, chat_id)
    if local_response is not None:
        return {"action": "chat", "response": local_response, "explanation": "Resposta local rápida."}

    system_prompt = (
        "Papel: seu nome é Voz e você é a assistente pessoal do usuário no Kali Bunker, dentro do Telegram. "
        f"Motor atual desta resposta: {active_ai_description()}. "
        "Personalidade: fale em português brasileiro natural, com clareza, inteligência, simpatia e segurança. "
        "Responda diretamente ao pedido real. Não use frases prontas como 'Entendi' seguidas de uma lista genérica "
        "do que você pode fazer. Não repita suas capacidades sem que perguntem. Adapte o nível de detalhe à pergunta; "
        "quando faltar uma informação essencial, faça somente a menor pergunta necessária. Admita incerteza em vez de inventar. "
        "Objetivo: resolver dúvidas, apoiar estudos e preparar ações autorizadas no PC. Para conversa normal, entregue primeiro "
        "a resposta útil e concreta. Para tarefas, inclua os próximos passos relevantes e pare quando o pedido estiver atendido. "
        "Formato: responda sempre em JSON válido, sem texto fora do JSON. "
        "Use {\"action\":\"chat\",\"response\":\"...\",\"explanation\":\"...\"} para conversa normal, "
        "estudos, dúvidas, programação, Linux, redes, segurança defensiva, organização, resumos, quizzes "
        "e explicações. Ao perguntarem qual modelo você usa, informe exatamente o motor atual declarado acima. "
        "Use {\"action\":\"status\",\"explanation\":\"...\"} para status do PC. "
        "Use {\"action\":\"shell\",\"command\":\"...\",\"explanation\":\"...\"} quando o usuário pedir "
        "uma ação real de terminal. Esse comando será executado pelo agente no PC Kali, não no servidor; "
        "pesquise pelo seu conhecimento o programa e os argumentos adequados ao objetivo, gere um único comando direto "
        "sem pipe, redirecionamento, ponto e vírgula, && ou substituição de shell. Para acessar uma máquina autorizada, "
        "você pode preparar ssh usuario@host comando como uma ação shell. "
        "Use {\"action\":\"send_path\",\"path\":\"...\",\"explanation\":\"...\"} "
        "quando o usuário pedir envio de arquivo ou pasta. Use {\"action\":\"webcam\",\"explanation\":\"...\"} "
        "para captura de webcam, {\"action\":\"install_package\",\"package\":\"...\",\"explanation\":\"...\"} "
        "para instalar um pacote apt, {\"action\":\"service\",\"service_action\":\"start|stop|restart\","
        "\"service_code\":\"BT|AUTH|SYS|WIFI|FILE|USB|BAN|MAIL\",\"explanation\":\"...\"} para serviço conhecido "
        "e {\"action\":\"purge_bot_messages\",\"explanation\":\"...\"} para apagar mensagens do bot. "
        "Use {\"action\":\"network_scan\",\"explanation\":\"...\"} para escanear ou listar dispositivos da rede local; "
        "nunca monte um comando nmap manual para esse pedido. "
        "Ações reais serão confirmadas pelo usuário antes "
        "de executar; não diga que executou algo. Não gere comandos destrutivos, persistentes ou com sudo "
        "a menos que o usuário peça explicitamente e a finalidade seja legítima."
    )
    if DEFAULT_SSH_PROFILE:
        system_prompt += (
            f" Perfil SSH conhecido e autorizado: servidor ou tropa = {DEFAULT_SSH_PROFILE}. "
            "Quando o usuário citar esse servidor, use esse destino. Como o agente não abre terminal interativo, "
            "inclua no ssh o comando remoto necessário; se o objetivo não estiver claro, pergunte o que deve ser feito."
        )
    memory = memory_context(prompt)
    if memory:
        system_prompt += "\nMemoria local da Voz que pode ser usada como contexto:\n" + memory
    messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]
    if chat_id:
        messages.extend(_load_ai_chat_history().get(str(chat_id), []))
    messages.append({"role": "user", "content": prompt})
    messages = _trim_ai_messages(messages, AI_INPUT_MAX_CHARS)
    for provider in ai_provider_order():
        models = [AI_MODEL] if provider == "openai" else [GEMINI_MODEL, GEMINI_FALLBACK_MODEL]
        for model in dict.fromkeys(models):
            try:
                if provider == "openai":
                    request_payload: dict[str, Any] = {"model": model, "input": messages}
                    if AI_MAX_OUTPUT_TOKENS > 0:
                        request_payload["max_tokens"] = AI_MAX_OUTPUT_TOKENS
                    text = response_text(openai_response(request_payload))
                else:
                    text = gemini_response(system_prompt, messages, model)
                plan = json_object_from_response(text)
            except (requests.RequestException, json.JSONDecodeError, ValueError, KeyError, IndexError, TypeError):
                continue
            if plan.get("action") not in {"chat", "shell", "send_path", "status", "webcam", "install_package", "service", "purge_bot_messages", "network_scan"}:
                continue
            normalized = {str(key): str(value) for key, value in plan.items()}
            if normalized.get("action") == "chat" and not normalized.get("response"):
                continue
            if normalized.get("action") == "chat":
                remember_ai_chat(chat_id, prompt, normalized["response"])
            return normalized

    return {
        "action": "chat",
        "response": fallback_chat_response(prompt, chat_id),
        "explanation": "IA online indisponível; resposta local.",
    }
