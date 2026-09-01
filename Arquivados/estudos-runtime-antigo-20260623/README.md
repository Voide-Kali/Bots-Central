# Estudos Bot (Telegram)

Bot de estudos: envia PDF/foto e gera resumo, questões e flashcards usando Groq.

## Instalação (Kali/Linux)

```bash
cd /home/voide/estudos-bot-main
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edite o `.env` e preencha `TELEGRAM_TOKEN` e `GROQ_API_KEY`.
Opcional: para o bot responder somente pra voce, defina `ALLOWED_CHAT_IDS` (separado por virgula).

## Rodar

```bash
cd /home/voide/estudos-bot-main
. .venv/bin/activate
python3 main.py
```

## Pegar seu chat_id (pra whitelist)

1) Inicie o bot e mande `/start` pra ele no Telegram.
2) Rode:

```bash
curl -s "https://api.telegram.org/botSEU_TOKEN/getUpdates"
```

Copie `message.chat.id` e coloque em `ALLOWED_CHAT_IDS`.
