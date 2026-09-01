# Bots-Central

Centralização dos bots de Telegram, Gmail, Estudos e controle remoto do notebook Kali em uma arquitetura com **servidor 24/7 + agente remoto**.

> Estado atual: código funcional validado por testes locais e GitHub Actions. O deploy real no servidor é uma etapa separada e só deve ser considerado concluído depois dos testes live descritos neste README.

---

## Visão geral

O objetivo do projeto é manter tudo que precisa funcionar continuamente no servidor e deixar o notebook Kali responsável apenas pelas ações físicas que realmente dependem dele.

```text
Celular
  |
  v
Telegram
  |
  v
HOME SERVER 24/7
Bots-Central
  |
  +-- Gmail
  +-- IA
  +-- Estudos
  +-- autenticação
  +-- scheduler
  +-- logs
  +-- SQLite / filas
  +-- pc_bridge
        |
        | Tailscale + SSH
        v
KALI NOTEBOOK
pc_agent
  |
  +-- status
  +-- Nmap
  +-- webcam
  +-- serviços
  +-- logs
  +-- lock/unlock
  +-- shutdown/reboot/suspend
  +-- cleanup/emergency
  +-- envio de arquivos
  +-- instalação de pacotes
```

### Regra arquitetural

- **Servidor** mantém Telegram, Gmail, IA, Estudos e persistência.
- **shared_core** concentra infraestrutura reutilizável.
- **pc_bridge** mantém a fila persistente de tarefas do notebook.
- **pc_agent** executa ações físicas no Kali.
- O servidor deve continuar operacional mesmo com o notebook desligado.

---

## Estado validado

Checkpoint funcional validado:

```text
55f5d776a1659a32bd7fc8aea2f72c781460c43d
test: cover shared core helpers
```

GitHub Actions do checkpoint:

| Job | Estado |
|---|---|
| Gmail | ✅ success |
| Estudos | ✅ success |
| Kali Bunker | ✅ success |

Run validado:

```text
33460746850
```

Validação local correspondente:

| Módulo | Resultado |
|---|---|
| Gmail | 56 passed, 5 skipped |
| Estudos | 2 passed |
| Kali Bunker | 172 passed |
| shared_core | 9 passed |
| compileall | ✅ |
| varredura de segredos | ✅ |

Esses resultados validam o código e os mocks/fixtures automatizados. Eles **não substituem teste live** com Telegram, Gmail OAuth, Tailscale, SSH, systemd e hardware real.

---

## Estrutura do repositório

```text
Bots-Central/
├── Ativos/
│   ├── gmail-telegram/
│   ├── estudos/
│   ├── kali-bunker/
│   └── shared_core/
├── Arquivados/
├── deploy/
│   └── server/
├── .github/
│   └── workflows/
├── CODEX_HANDOFF.md
├── gerenciar.sh
├── verificar.sh
└── README.md
```

### Ativos/gmail-telegram

Bot central responsável por:

- Telegram principal;
- Gmail;
- notificações;
- outbox persistente;
- recuperação de entregas;
- IA ligada ao fluxo central;
- painéis;
- fila do PC;
- publicação dos resultados do `pc_agent`.

### Ativos/estudos

Bot de estudos responsável por:

- PDFs;
- resumos;
- perguntas;
- flashcards;
- callbacks;
- IA aplicada ao conteúdo;
- controle de concorrência durante geração;
- limpeza de arquivos temporários.

### Ativos/kali-bunker

Contém:

- lógica de segurança;
- controle remoto;
- interpretação de ações;
- `pc_agent`;
- serviços systemd do notebook;
- funções de telemetria e operações locais.

### Ativos/shared_core

Código comum reutilizável.

Atualmente contém:

```text
shared_core/
├── ai_provider.py
├── telegram_auth.py
└── tests/
```

Responsabilidades:

- seleção/ordem de providers;
- infraestrutura comum de IA;
- autorização Telegram compartilhada.

Regra importante:

```text
shared_core.ai_provider -> conversa com modelos
remote_control.py       -> interpreta intenção/resposta
pc_agent                -> executa ação física
```

A camada de IA não deve executar diretamente comandos físicos.

---

## Gmail

O módulo Gmail possui persistência própria para evitar perda de notificações.

Fluxo simplificado:

```text
Gmail API
   |
   v
processamento
   |
   v
outbox SQLite
   |
   +-- pending
   +-- sending
   +-- sent
   +-- failed
   +-- filtered
   |
   v
Telegram
```

A fila suporta:

- retry;
- backoff;
- lease;
- recuperação após restart;
- mensagens pendentes;
- registro de mensagens já processadas.

Em produção, o banco deve ficar fora do código:

```text
/var/lib/bots-central/gmail_bot.db
```

Credenciais Gmail devem permanecer fora do Git.

Exemplo de destino:

```text
/etc/bots-central/credentials/
```

---

## Fila do notebook: pc_bridge

O `pc_bridge` conecta o servidor ao agente do notebook.

Estados de uma tarefa:

```text
queued
  |
  v
running
  |
  +--> completed
  +--> failed
  +--> canceled
```

Recursos preservados:

- SQLite WAL;
- leases;
- heartbeat;
- cancelamento;
- recuperação de lease expirado;
- artifacts;
- limites de tamanho;
- persistência;
- entrega posterior do resultado ao Telegram.

Produção deve usar:

```text
PC_BRIDGE_DB=/var/lib/bots-central/pc_bridge.db
PC_BRIDGE_ARTIFACT_DIR=/var/lib/bots-central/pc-artifacts
PC_AGENT_ID=kali-principal
```

O servidor e qualquer comando executado via SSH precisam enxergar **o mesmo banco e o mesmo diretório de artifacts**.

Nunca mantenha:

```text
servidor -> pc_bridge.db A
agente   -> pc_bridge.db B
```

---

## pc_agent

O `pc_agent` roda no notebook Kali e consulta o servidor por Tailscale + SSH.

Ações suportadas pelo agente incluem:

- status;
- network scan;
- webcam;
- shell controlado;
- serviços;
- logs de serviços;
- lock;
- unlock;
- shutdown;
- reboot;
- suspend;
- cleanup;
- emergency;
- envio de arquivo;
- instalação de pacote.

As ações privilegiadas devem permanecer **fail-closed**.

Ou seja, ausência de configuração nunca deve habilitar automaticamente:

- webcam;
- shell;
- package install;
- shutdown;
- reboot;
- suspend;
- cleanup;
- outras operações privilegiadas.

---

## Servidor 24/7

Layout de produção recomendado:

```text
/opt/bots-central/
├── releases/
│   └── <commit-sha>/
├── current -> releases/<commit-sha>
└── venvs/

/etc/bots-central/
├── bots-central.env
├── studies.env
├── gmail-config.py
├── studies-config.py
└── credentials/

/var/lib/bots-central/
├── gmail_bot.db
├── pc_bridge.db
└── pc-artifacts/
```

### Serviços do servidor

Objetivo:

```text
bots-central.service
ACTIVE + ENABLED

bots-central-studies.service
ACTIVE + ENABLED
```

O serviço central não deve depender de terminal aberto.

Depois de crash ou reboot, systemd deve subir novamente os processos.

---

## Telegram e tokens

Central e Estudos atualmente podem operar como processos de long polling separados.

**Dois processos não devem usar simultaneamente o mesmo token de bot Telegram.**

Se os dois serviços forem mantidos separados:

```text
Bots Central -> token próprio
Estudos      -> token próprio
```

Também mantenha autorização restrita por chat/usuário.

Variáveis relevantes:

```text
TELEGRAM_TOKEN
TELEGRAM_CHAT_ID
TELEGRAM_ALLOWED_USER_IDS
ALLOWED_CHAT_IDS
```

Nunca coloque valores reais no README, commits ou logs públicos.

---

## IA

Providers previstos pelo projeto:

- Gemini;
- OpenAI;
- Groq, quando configurado e suportado.

A seleção de provider deve preferir configuração por ambiente.

Evite manter modelo descontinuado como comportamento obrigatório.

Exemplo:

```text
AI_PROVIDER=auto

GEMINI_API_KEY=
GEMINI_MODEL=

OPENAI_API_KEY=

GROQ_API_KEY=
GROQ_MODEL=
```

O projeto deve tratar:

- timeout;
- 401/403;
- 429;
- Retry-After;
- 5xx;
- resposta vazia;
- resposta inválida;
- ausência de chave;
- fallback entre providers.

---

## Dependências

Atualmente Gmail e Estudos usam versões diferentes de algumas dependências.

Por exemplo:

```text
Gmail:
python-telegram-bot 22.7

Estudos:
python-telegram-bot 21.6
```

Por isso, no deploy atual é mais seguro manter ambientes virtuais separados até uma normalização futura.

Exemplo:

```text
/opt/bots-central/venvs/gmail
/opt/bots-central/venvs/studies
```

Não instale dependências específicas do Kali no servidor sem necessidade.

---

## Branches importantes

### refactor/server-central-foundation

Branch de estabilização atual.

Contém o checkpoint funcional validado por CI.

Não fazer merge automático para `main` durante o deploy.

### ops/deploy-tooling

Branch auxiliar com ferramentas de deploy.

Inclui utilitários para:

- preflight;
- instalação;
- ativação;
- verificação;
- rollback;
- systemd;
- layout de releases;
- configuração persistente.

O tooling deve estar com CI verde antes de ser usado no servidor.

### perf/central-speed-v2

Branch experimental de performance.

Não é requisito para colocar o sistema online.

Primeiro:

```text
funciona
-> fica estável
-> vai para produção
-> depois otimiza
```

---

## Deploy

A aplicação implantada deve usar um SHA explicitamente validado.

Exemplo usando o checkpoint atual:

```bash
EXPECTED_SHA=55f5d776a1659a32bd7fc8aea2f72c781460c43d
```

O tooling de deploy fica na branch:

```text
ops/deploy-tooling
```

Fluxo esperado:

```bash
EXPECTED_SHA=<sha-validado> bash deploy/server/preflight.sh

sudo EXPECTED_SHA=<sha-validado> bash deploy/server/install.sh

sudoedit /etc/bots-central/bots-central.env
sudoedit /etc/bots-central/studies.env
sudoedit /etc/bots-central/gmail-config.py
sudoedit /etc/bots-central/studies-config.py

sudo bash deploy/server/activate.sh
sudo bash deploy/server/verify.sh
```

### Por que usar SHA fixo

O deploy deve copiar uma release baseada no commit validado, e não simplesmente o working tree atual.

Isso evita enviar para produção:

- alteração local não commitada;
- arquivo de teste temporário;
- segredo;
- código ainda não validado.

---

## Rollback

A instalação por releases deve manter versões anteriores em:

```text
/opt/bots-central/releases/
```

Em caso de regressão:

```bash
sudo bash deploy/server/rollback.sh <sha-anterior>
```

O rollback deve apenas trocar a release ativa e reiniciar os serviços necessários.

Bancos e credenciais permanecem fora da release.

---

## Testes antes de produção

Executar:

### Gmail

```bash
cd Ativos/gmail-telegram
python -m unittest discover -s tests -v
```

### Estudos

```bash
cd Ativos/estudos
python -m unittest discover -s tests -v
```

### Kali Bunker

```bash
cd Ativos/kali-bunker
python -m pytest -q
```

### shared_core

```bash
python -m unittest discover -s Ativos/shared_core/tests -v
```

### Compile

```bash
python -m compileall -q \
  Ativos/gmail-telegram \
  Ativos/estudos \
  Ativos/kali-bunker \
  Ativos/shared_core
```

Também execute os scanners/prepublish checks existentes antes de publicar.

---

## Checklist live

CI verde não prova integrações externas.

Antes de declarar produção pronta, validar:

### Servidor

- [ ] `bots-central.service` active
- [ ] `bots-central.service` enabled
- [ ] `bots-central-studies.service` active
- [ ] `bots-central-studies.service` enabled
- [ ] sem restart loop

### Telegram

- [ ] `/start`
- [ ] `/statusbot`
- [ ] `/painel`
- [ ] autorização correta

### Gmail

- [ ] OAuth real
- [ ] contas carregadas
- [ ] leitura funciona
- [ ] `/verificar`
- [ ] outbox persiste após restart

### IA

- [ ] provider real responde
- [ ] fallback real funciona
- [ ] nenhuma ação física é executada sem validação

### Estudos

- [ ] bot responde
- [ ] PDF pequeno real
- [ ] resumo
- [ ] perguntas
- [ ] flashcards

### pc_bridge / pc_agent

- [ ] Tailscale conectado
- [ ] SSH BatchMode
- [ ] pc_agent active
- [ ] pc_agent enabled
- [ ] job queued
- [ ] job running
- [ ] job completed
- [ ] resultado retorna ao Telegram
- [ ] cancelamento funciona

### Notebook offline

- [ ] servidor continua Telegram
- [ ] Gmail continua
- [ ] IA continua
- [ ] Estudos continua
- [ ] jobs do notebook não corrompem
- [ ] pc_agent reconecta quando volta

---

## Operações perigosas

Não teste destrutivamente apenas para preencher checklist.

Evite executar sem necessidade real:

- shutdown;
- reboot;
- cleanup agressivo;
- emergency;
- instalação aleatória de pacote.

Essas ações podem ser validadas até confirmação/fila e testadas fisicamente somente quando houver uma janela segura.

---

## Segurança

Regras mínimas:

- secrets fora do Git;
- `.env` com permissão restrita;
- OAuth tokens fora do repositório;
- chaves SSH fora do repositório;
- bancos SQLite fora da release;
- usuário de serviço dedicado;
- nenhuma ação privilegiada habilitada por ausência de configuração;
- SSH sem senha interativa para o agente, mas sem desabilitar verificação de host;
- chave SSH dedicada ao agente quando possível;
- nenhum token impresso em relatórios.

Nunca versionar:

```text
.env
token.json
*_token.json
credentials reais
client_secret real
*.db
id_rsa
id_ed25519
API keys
Telegram tokens
OAuth tokens
```

---

## Comandos úteis

### Git

```bash
git status --short --branch
git log -1 --oneline
```

### Servidor

```bash
systemctl status bots-central.service
systemctl status bots-central-studies.service

journalctl -u bots-central.service -n 100 --no-pager
journalctl -u bots-central-studies.service -n 100 --no-pager
```

### Notebook

```bash
systemctl status kali-bunker-pc-agent.service
journalctl -u kali-bunker-pc-agent.service -n 100 --no-pager
```

### Tailscale

```bash
tailscale status
```

---

## O que ainda não deve ser tratado como validado

Até a execução do deploy live, permanecem dependentes de ambiente real:

- Telegram Bot API;
- Gmail OAuth real;
- servidor 24/7;
- Tailscale servidor ↔ notebook;
- SSH real;
- webcam física;
- Nmap real;
- serviços locais reais;
- lock/unlock;
- shutdown/reboot/suspend;
- cleanup/emergency;
- instalação real de pacotes;
- transferência real de arquivos.

Quando esses testes forem executados com sucesso, esta seção deve ser atualizada com o estado de produção.

---

## Ordem de prioridade do projeto

```text
1. correção
2. estabilidade
3. segurança
4. funcionamento live
5. recuperação
6. performance
7. refinamento
```

A meta não é ter o bot mais sofisticado possível.

A meta é ter um sistema que:

```text
inicia
responde
persiste
recupera
reconecta
e continua funcionando
```

mesmo quando o notebook não está disponível.
