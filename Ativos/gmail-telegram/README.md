# Kali Bunker · Gmail Monitor

Um bot do Telegram que monitora múltiplas contas Gmail simultaneamente e usa Inteligência Artificial para resumir os emails recebidos, tudo em tempo real direto no seu celular.

## O que ele faz

- Monitora várias contas Gmail ao mesmo tempo — configure quantas contas quiser
- Notifica no Telegram assim que chega um email novo, sem precisar abrir o Gmail
- Pode resumir conteúdo com IA via Groq quando `AI_EMAIL_SUMMARY_ENABLED=1`; por padrão, nenhum conteúdo de e-mail é enviado ao provedor externo
- Mantém uma caixa de saída SQLite que recupera entregas após reinícios e reduz duplicações concorrentes
- Exibe uma central unificada com estado dos serviços do Kali Bunker
- Mostra CPU, memória, disco, temperatura e conexão Bluetooth
- Permite desligar, reiniciar, suspender o PC e iniciar a limpeza do sistema com confirmação
- Bloqueia a tela, executa modo emergência, controla serviços permitidos e consulta logs
- Envia relatório manual ou diário, alerta bateria/energia e faz scan rápido da rede
- Captura foto da webcam local com confirmação
- Silencia alertas, ativa modo manutenção e registra histórico de ações remotas
- Faz checagem de integridade, permissões e atualização controlada do sistema
- A Voz aceita mensagens de texto, áudios/voz do Telegram e anexos para usar como contexto

## Tecnologias usadas

- Python 3.11+
- Gmail API — leitura dos emails via OAuth2 (sem salvar senha)
- python-telegram-bot — integração com o Telegram
- Groq API — IA gratuita para resumir os emails (modelo Llama 3)
- SQLite — banco de dados local para controlar emails já notificados
- ffmpeg/Whisper local ou OpenAI — transcrição opcional de áudios enviados para a Voz

## Custo

100% gratuito. Todas as APIs usadas têm plano gratuito mais do que suficiente para uso pessoal.

## Configuracao

1. Clone o repositório
2. Crie o ambiente: `python3 -m venv venv`
3. Instale as dependências: `venv/bin/pip install -r requirements.txt`
4. Copie `.env.example` para `.env` e preencha `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` e, para grupos, `TELEGRAM_ALLOWED_USER_IDS`
5. Copie `config.example.py` para `config.py` e ajuste as contas Gmail
6. Crie um cliente OAuth2 do tipo Aplicativo para computador no Google Cloud
7. Salve o JSON como `credentials/client_secret.json`
8. Adicione todas as contas em Google Auth Platform > Público-alvo > Usuários de teste
9. Execute `venv/bin/python authorize.py` e escolha a conta indicada em cada etapa
10. Opcionalmente, configure `GROQ_API_KEY` e ative `AI_EMAIL_SUMMARY_ENABLED=1` para gerar resumos externos
11. Rode: `venv/bin/python main.py`

## Comandos do bot

| Comando     | Descricao                          |
|-------------|------------------------------------|
| /painel     | Abrir a central Kali Bunker        |
| /seguranca  | Ver estado das defesas             |
| /sistema    | Ver telemetria do computador        |
| /gmail      | Abrir o painel Gmail                |
| /contas     | Listar todas as contas monitoradas |
| /verificar  | Forcar uma verificacao imediata    |
| /resumo     | Ver status rapido do sistema       |
| /relatorio  | Gerar relatorio completo           |
| /servicos   | Controlar modulos permitidos       |
| /servico    | Controlar modulo por argumento     |
| /logs AUTH  | Ver logs de um modulo              |
| /scan       | Escanear a rede local              |
| /bloquear   | Bloquear a tela                    |
| /desbloquear| Desbloquear a tela                 |
| /emergencia | Bloquear e reiniciar modulos       |
| /silenciar  | Pausar alertas temporariamente     |
| /manutencao | Ativar modo manutencao             |
| /integridade| Checar integridade do bot          |
| /permissoes | Ver permissoes/dependencias        |
| /historico  | Ver historico de acoes remotas     |
| /atualizar  | Menu de atualizacao do sistema     |
| /webcam     | Capturar foto com confirmacao      |
| /ia         | Conversar com a Voz por texto/áudio|
| /senhas     | Abrir cofre de senhas da Voz       |
| /desligar   | Abrir confirmacao de desligamento  |
| /reiniciar  | Abrir confirmacao de reinicio      |
| /suspender  | Abrir confirmacao de suspensao     |
| /limpeza    | Abrir confirmacao de limpeza       |
| /ajuda      | Ver ajuda da central                |

## Estrutura do projeto

```
gmail-telegram-bot/
├── main.py           # Entry point
├── config.py         # Configuracoes (nao subir no git)
├── bot.py            # Logica do Telegram
├── gmail_client.py   # Gmail API
├── summarizer.py     # Resumos com Groq
├── db.py             # SQLite
├── requirements.txt
└── credentials/      # Nao subir no git
```

## Seguranca

O bot exige simultaneamente o chat configurado e um `effective_user` autorizado. `TELEGRAM_ALLOWED_USER_IDS` aceita IDs numéricos separados por vírgula, por exemplo `123456789,987654321`. Se ficar vazio, o bot usa `TELEGRAM_CHAT_ID` como único usuário permitido: isso é seguro para conversa privada e bloqueia membros de grupos até a lista ser configurada.

As ações remotas de desligar, reiniciar, suspender e limpar ficam desativadas por padrão. Ative somente a função necessária no `.env`, depois de revisar o comando e limitar o `sudoers`.

O cofre e a webcam também exigem ativação explícita com `REMOTE_VAULT_ENABLED=1` e `REMOTE_WEBCAM_ENABLED=1`. Sem essas flags, tanto os botões diretos quanto ações propostas pela Voz são bloqueados. Bots do Telegram não usam conversas secretas com criptografia ponta a ponta; não envie senha mestra ou segredos pelo bot salvo se aceitar conscientemente esse risco.

Para o botão de limpeza funcionar, o usuário do serviço precisa conseguir executar o comando definido em `CLEANUP_COMMAND` sem senha. Configure um caminho absoluto, por exemplo:

```bash
sudo /caminho/absoluto/Kali-Bunker-main/limpeza-semanal.sh
```

O controle de serviços usa uma whitelist interna dos módulos do Kali Bunker e executa `systemctl start|stop|restart`. O bot bloqueia o comando de parar o próprio `gmail-telegram-bot.service` para não cortar o acesso remoto. Para funcionar sem senha, libere apenas essas unidades no sudoers ou rode o serviço com permissões adequadas.

Para os botões de energia, deixe `SHUTDOWN_COMMAND`, `REBOOT_COMMAND` e `SUSPEND_COMMAND` vazios para o bot tentar os comandos padrão em sequência.

Desligamento tenta `systemctl poweroff`, desligamento pela sessão KDE via D-Bus, `sudo -n /usr/sbin/shutdown -h now` e `/usr/sbin/shutdown -h now`.
Reinício tenta `systemctl reboot`, reinício pela sessão KDE via D-Bus, `sudo -n /usr/sbin/shutdown -r now`, `/usr/sbin/shutdown -r now`, `sudo -n /usr/sbin/reboot` e `/usr/sbin/reboot`.
Suspensão tenta primeiro o PowerDevil/KDE via D-Bus (`suspendToRam`) e depois `systemctl suspend`.
Bloqueio de tela tenta `loginctl lock-sessions` e bloqueio via D-Bus.
Desbloqueio de tela tenta a sessão gráfica do usuário `LOCK_USER`, depois `loginctl unlock-sessions` e fallbacks via D-Bus. O bot continua funcionando com a tela bloqueada porque roda como serviço systemd; se a máquina estiver suspensa, desligada ou sem rede, o Telegram não consegue alcançá-lo.

Se quiser forçar o caminho com sudo, defina no `.env`:

```bash
SHUTDOWN_COMMAND=sudo -n /usr/sbin/shutdown -h now
REBOOT_COMMAND=sudo -n /usr/sbin/shutdown -r now
SUSPEND_COMMAND=
LOCK_COMMAND=loginctl lock-sessions
UNLOCK_COMMAND=loginctl unlock-sessions
```

Nesse caso, libere esses comandos no sudoers somente para o usuário que executa o serviço e ative apenas as ações desejadas com `REMOTE_SHUTDOWN_ENABLED=1`, `REMOTE_REBOOT_ENABLED=1`, `REMOTE_SUSPEND_ENABLED=1` ou `REMOTE_CLEANUP_ENABLED=1`.

Recursos extras configuráveis no `.env`:

```bash
AI_EMAIL_SUMMARY_ENABLED=0
GROQ_API_KEY=
EMAIL_DELIVERY_MAX_ATTEMPTS=8
EMAIL_DELIVERY_LEASE_SECONDS=300
EMAIL_DELIVERY_BACKOFF_SECONDS=30
EMAIL_DELIVERY_MAX_BACKOFF_SECONDS=3600
EMAIL_DELIVERY_BATCH_SIZE=20
NETWORK_SCAN_TARGET=192.168.3.0/24
NETWORK_SCAN_INTERFACE=
NETWORK_SCAN_TIMEOUT_SECONDS=90
OPENAI_API_KEY=
AI_AUDIO_MAX_MB=25
AI_AUDIO_TIMEOUT_SECONDS=180
AI_AUDIO_OPENAI_MODEL=whisper-1
AI_AUDIO_LANGUAGE=pt
AI_AUDIO_THREADS=4
AI_AUDIO_WHISPER_CPP_BIN=
AI_AUDIO_WHISPER_CPP_MODEL=
AI_AUDIO_WHISPER_CPP_BACKEND=
LOCAL_WHISPER_MODEL=base
WEBCAM_RESOLUTION=1280x720
BATTERY_ALERTS_ENABLED=1
BATTERY_LOW_PERCENT=25
BATTERY_ALERT_INTERVAL_SECONDS=1800
DAILY_REPORT_ENABLED=0
DAILY_REPORT_HOUR=9
DAILY_REPORT_MINUTE=0
SMART_ALERTS_ENABLED=1
SMART_ALERT_COOLDOWN_SECONDS=1800
SMART_ALERT_DURATION_SECONDS=180
SMART_CPU_PERCENT=90
SMART_DISK_PERCENT=90
SMART_TEMP_C=82
APT_UPGRADE_COMMAND=
```

`AI_EMAIL_SUMMARY_ENABLED` é uma opção explícita de privacidade. Com o valor padrão `0`, nenhum conteúdo de e-mail é enviado ao Groq e o bot usa somente a prévia fornecida pelo Gmail. Ao definir `1`, remetente, assunto e até 1.500 caracteres do corpo/prévia são enviados ao provedor configurado para produzir o resumo.

### Entrega durável Gmail → Telegram

Antes da primeira tentativa, o bot grava no SQLite somente a conta, o ID opaco da mensagem, estado, tentativas e horários. Remetente, assunto, corpo e prévia não entram na caixa de saída. Após um reinício, o conteúdo é consultado novamente pelo ID na API Gmail.

Uma reivindicação atômica com prazo (`EMAIL_DELIVERY_LEASE_SECONDS`) impede dois trabalhadores de enviarem simultaneamente o mesmo item. Falhas usam backoff exponencial entre `EMAIL_DELIVERY_BACKOFF_SECONDS` e `EMAIL_DELIVERY_MAX_BACKOFF_SECONDS`; depois de `EMAIL_DELIVERY_MAX_ATTEMPTS`, o item fica em `failed` até uma intervenção explícita. O comando `/verificar` reabre esses itens para uma nova rodada, e `EMAIL_DELIVERY_BATCH_SIZE` limita o trabalho de cada verificação.

O estado só muda para `sent` após o Telegram confirmar a chamada. Ainda existe uma janela inevitável: se o Telegram aceitar a mensagem e o processo cair antes do commit SQLite, a recuperação poderá reenviá-la. A API Bot do Telegram não fornece uma chave de idempotência para eliminar com segurança essa última duplicata; escolher o contrário poderia perder notificações.

O scan usa `arp-scan` quando disponível, com fallback para `nmap -sn`. Se `NETWORK_SCAN_TARGET` ficar vazio, o bot escolhe a rede IPv4 conectada e ignora interfaces virtuais/VPN; use `NETWORK_SCAN_INTERFACE=wlan0` se quiser fixar uma placa. O botão de banimento registra o IP via `bunkerctl ban add` e só aplica firewall automaticamente se o sudoers permitir o comando sem senha. A webcam usa `fswebcam`. O relatório diário fica desligado por padrão; ative com `DAILY_REPORT_ENABLED=1`.
Para a Voz ouvir áudios, use `whisper.cpp` local, instale o comando `whisper` no ambiente do bot ou configure `OPENAI_API_KEY`; `ffmpeg` é usado para preparar o áudio antes da transcrição. O bot tenta primeiro `whisper.cpp` local, depois `whisper` Python e só então OpenAI.
O menu `/atualizar` consulta pacotes atualizáveis sem sudo. O upgrade fica desativado por padrão; configure `APT_UPGRADE_COMMAND=sudo -n /usr/bin/apt upgrade -y` apenas se o sudoers estiver liberado sem senha.
O histórico de ações fica no SQLite local `gmail_bot.db` e não armazena tokens.

### Agente remoto do PC

O Telegram, o Gmail e a IA permanecem no servidor. O módulo `pc_bridge.py`
mantém uma fila SQLite persistente, enquanto `pc_agent.py` roda no Kali e
busca tarefas por SSH. Se o PC estiver desligado, as tarefas continuam como
`aguardando` e são executadas quando ele voltar.

Comandos principais:

```text
/pc                 conexão e telemetria do PC
/tarefas            fila e histórico
/cancelar ID        cancela uma tarefa
/scan [REDE/CIDR]   executa Nmap no PC
/webcam             solicita uma foto do PC
```

Mensagens comuns também podem gerar tarefas pela Voz IA. Comandos, Nmap,
serviços, SSH e webcam mostram uma confirmação antes de entrar na fila. O
resultado e eventuais arquivos retornam automaticamente ao Telegram.

No PC, o serviço é `kali-bunker-pc-agent.service`:

```bash
systemctl --user status kali-bunker-pc-agent.service
journalctl --user -u kali-bunker-pc-agent.service -f
```

Nunca suba o `config.py`, o `.env` ou a pasta `credentials/` para o GitHub. Eles contêm suas chaves e tokens pessoais. O `.gitignore` ja esta configurado para ignora-los.

## Governança

- [LICENSE](LICENSE)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CHANGELOG.md](CHANGELOG.md)

## Licenca

MIT License — use a vontade.
