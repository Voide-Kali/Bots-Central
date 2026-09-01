# Central de Estudos

Bot do Telegram para estudo guiado com suporte a PDF, imagens, chat, resumos, questões e flashcards. Usa Gemini ou Groq.

## Componentes

- `main.py`: fluxo principal do bot
- `ia.py`: integração com modelos de IA
- `pdf_utils.py`: leitura e preparação de PDF
- `config.py` e `config.example.py`: configuração local
- `systemd/estudos-bot.service`: execução como serviço

## Instalação

```bash
git clone https://github.com/Voide-Kali/estudos-bot.git /home/voide/Projetos/estudos-bot
cd /home/voide/Projetos/estudos-bot
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Configuração

- preencha `TELEGRAM_TOKEN`;
- escolha pelo menos um provedor entre `GEMINI_API_KEY` e `GROQ_API_KEY`;
- use `AI_PROVIDER=auto` para preferir Gemini e cair para Groq se precisar;
- ajuste `ALLOWED_CHAT_IDS` para restringir o acesso.

## Execução

```bash
. .venv/bin/activate
python3 main.py
```

## Serviço systemd do usuário

O arquivo fornecido usa o caminho canônico
`/home/voide/Projetos/estudos-bot` e não precisa de `sudo`.

```bash
mkdir -p ~/.config/systemd/user
install -m 0600 systemd/estudos-bot.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now estudos-bot.service
systemctl --user status estudos-bot.service
```

Para acompanhar os registros, use
`journalctl --user -u estudos-bot.service -f`.

## Estrutura

```text
estudos-bot/
├── main.py
├── ia.py
├── pdf_utils.py
├── config.py
├── config.example.py
├── systemd/
└── README.md
```

## Governança

- [LICENSE](LICENSE)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CHANGELOG.md](CHANGELOG.md)
