"""Provedores de IA da Central de Estudos: Gemini com fallback Groq."""

from __future__ import annotations

import base64
import logging

import requests

import config


logger = logging.getLogger(__name__)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_VISION_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"


def _missing_key_msg() -> str:
    return (
        "A inteligência artificial não está configurada. "
        "Defina GEMINI_API_KEY ou GROQ_API_KEY no arquivo .env."
    )


def _gemini_text(prompt: str, max_tokens: int, temperature: float) -> str:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=config.GEMINI_API_KEY)
    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
        ),
    )
    return (response.text or "").strip()


def _groq_text(prompt: str, max_tokens: int, temperature: float) -> str:
    response = requests.post(
        GROQ_URL,
        headers={
            "Authorization": f"Bearer {config.GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": config.GROQ_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        },
        timeout=45,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"].strip()


def chamar_ia(prompt: str, max_tokens: int = 1500, temperature: float = 0.4) -> str:
    provider = config.active_ai_provider()
    if provider == "indisponivel":
        return _missing_key_msg()
    try:
        if provider == "gemini":
            return _gemini_text(prompt, max_tokens, temperature)
        return _groq_text(prompt, max_tokens, temperature)
    except Exception as exc:
        logger.error("Erro no provedor %s: %s", provider, exc)
        return "A IA está temporariamente indisponível. Tente novamente em alguns instantes."


def chamar_groq(prompt: str, max_tokens: int = 1500) -> str:
    """Compatibilidade com chamadas antigas."""
    return chamar_ia(prompt, max_tokens=max_tokens)


def chamar_groq_com_imagem(pergunta: str, imagem_bytes: bytes) -> str:
    """Analisa imagens usando o provedor ativo."""
    provider = config.active_ai_provider()
    if provider == "indisponivel":
        return _missing_key_msg()

    prompt = pergunta or "Analise esta imagem em português para fins de estudo."
    try:
        if provider == "gemini":
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=config.GEMINI_API_KEY)
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=[
                    types.Part.from_bytes(data=imagem_bytes, mime_type="image/jpeg"),
                    prompt,
                ],
                config=types.GenerateContentConfig(max_output_tokens=1200),
            )
            return (response.text or "").strip()

        image_b64 = base64.b64encode(imagem_bytes).decode("utf-8")
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {config.GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_VISION_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_b64}"
                                },
                            },
                            {"type": "text", "text": prompt},
                        ],
                    }
                ],
                "max_tokens": 1200,
            },
            timeout=45,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        logger.error("Erro de visão no provedor %s: %s", provider, exc)
        return "Não foi possível analisar a imagem agora."


def gerar_resumo(texto: str) -> str:
    return chamar_ia(
        "Resuma o texto em português, usando tópicos claros, conceitos-chave "
        f"e no máximo 400 palavras:\n\n{texto[:12000]}",
        max_tokens=1200,
    )


def gerar_questoes(texto: str) -> str:
    return chamar_ia(
        "Crie 5 questões de múltipla escolha em português com alternativas A, B, C e D. "
        "Apresente o gabarito comentado ao final.\n\n"
        f"Texto:\n{texto[:12000]}",
        max_tokens=1800,
    )


def gerar_flashcards(texto: str) -> str:
    return chamar_ia(
        "Crie 8 flashcards em português. Use o formato "
        "FRENTE: pergunta e VERSO: resposta, separados por ---.\n\n"
        f"Texto:\n{texto[:12000]}",
        max_tokens=1800,
    )


def chat(historico: list, mensagem: str) -> str:
    conversation = [
        "Você é um assistente de estudos objetivo e didático. "
        "Responda sempre em português e adapte a explicação ao nível da pergunta."
    ]
    for item in historico[-10:]:
        role = "Aluno" if item.get("role") == "user" else "Assistente"
        conversation.append(f"{role}: {item.get('content', '')}")
    conversation.append(f"Aluno: {mensagem}")
    conversation.append("Assistente:")
    return chamar_ia("\n\n".join(conversation), max_tokens=1400, temperature=0.6)
