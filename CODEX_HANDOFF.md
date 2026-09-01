# Handoff para Codex

Branch de trabalho: `refactor/server-central-foundation`

## Objetivo

Transformar o projeto em uma central executada 24/7 no servidor, mantendo o notebook Kali como agente remoto opcional.

## Já implementado nesta branch

- autorização Telegram exige chat permitido **e** usuário permitido;
- `TELEGRAM_ALLOWED_USER_IDS` agora é validado;
- caminho do Kali Bunker deixou de ficar fixo dentro de `bot.py`;
- suporte a `KALI_BUNKER_DIR` configurável;
- CI criado na raiz do monorepo;
- teste dedicado para autorização Telegram;
- unit systemd inicial para servidor em `deploy/server/bots-central.service`;
- exemplo de ambiente de servidor em `deploy/server/bots-central.env.example`.

## Próxima etapa obrigatória

1. Rodar toda a suíte de testes antes de refatorar mais.
2. Corrigir qualquer regressão introduzida ou já existente.
3. Criar um núcleo central compartilhado para configuração, autenticação, logging e IA.
4. Extrair o roteamento de IA duplicado de Gmail/Estudos/Kali para um único módulo.
5. Separar completamente ações locais do notebook das ações do servidor.
6. Manter `pc_bridge.py` como fila persistente no servidor ou migrá-lo sem perder semântica de lease, cancelamento e recuperação.
7. Fazer o notebook executar apenas `pc_agent`.
8. Eliminar scripts systemd antigos/conflitantes depois que a nova implantação estiver validada.
9. Não migrar para PostgreSQL/Docker/microserviços sem necessidade demonstrada.
10. Não colocar tokens, OAuth ou credenciais no Git.

## Arquitetura alvo

```text
Celular -> Telegram -> Servidor 24/7
                      |
                      +-- Gmail
                      +-- IA
                      +-- Estudos
                      +-- Lembretes
                      +-- SQLite / filas
                      |
                      +-- Tailscale/SSH -> Notebook Kali -> pc_agent
```

## Regras de segurança

- ações privilegiadas devem permanecer desativadas por padrão;
- toda ação remota sensível deve exigir autorização por usuário e confirmação;
- manter whitelist de serviços/comandos;
- nenhuma porta administrativa deve ser publicada diretamente na Internet;
- preferir Tailscale + SSH com chave dedicada para o agente;
- preservar limites de tamanho, timeout, cancelamento e validação de caminhos existentes.

## Critério de conclusão

O servidor deve continuar respondendo a Telegram, Gmail e IA com o notebook completamente desligado. Quando o notebook voltar, o agente deve reconectar e processar tarefas pendentes sem iniciar uma segunda instância do bot Telegram.
