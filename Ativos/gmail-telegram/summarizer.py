"""
Resumidor de emails usando Groq
"""

import logging
import os

import requests
import config
from config import GROQ_API_KEY, GROQ_MODEL, SUMMARY_MAX_TOKENS

logger = logging.getLogger(__name__)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def external_summary_enabled() -> bool:
    """Exige consentimento explícito antes de enviar conteúdo de e-mail."""
    value = getattr(
        config,
        "AI_EMAIL_SUMMARY_ENABLED",
        os.environ.get("AI_EMAIL_SUMMARY_ENABLED", "0"),
    )
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def summarize_email(sender: str, subject: str, body: str, snippet: str) -> str:
    """
    Gera um resumo curto do email usando o Groq.
    Retorna o snippet original se a API falhar.
    """
    if not external_summary_enabled():
        return snippet or "(sem prévia)"

    if not GROQ_API_KEY or GROQ_API_KEY == "SUA_GROQ_API_KEY_AQUI" or not GROQ_MODEL:
        return snippet or "(sem prévia)"

    content = body if body else snippet
    if not content:
        return "(sem conteúdo)"

    prompt = f"""Resuma este email em português em no máximo 2 frases curtas e diretas.
Não use introduções como "O email diz" ou "O remetente escreve". Vá direto ao ponto.

De: {sender}
Assunto: {subject}
Conteúdo: {content[:1500]}

Resumo:"""

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": SUMMARY_MAX_TOKENS,
                "temperature": 0.3,
            },
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        logger.warning("Groq retornou status %s.", response.status_code)
        return snippet or "(sem prévia)"

    except Exception as exc:
        logger.error("Erro ao chamar Groq: %s", exc)
        return snippet or "(sem prévia)"
