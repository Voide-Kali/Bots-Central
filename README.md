# Central dos bots

Esta pasta é o painel de organização. Os projetos reais continuam nos caminhos
canônicos usados pelos serviços; os atalhos daqui não guardam tokens nem bancos.

## Arquitetura atual

| Nome | Projeto canônico | Papel | Operação normal |
|---|---|---|---|
| Gmail central | `/home/voide/Projetos/gmail-telegram-bot` | Gmail e painel remoto do Kali Bunker | ativo |
| Estudos | `/home/voide/Projetos/estudos-bot` | PDFs, imagens, resumos e exercícios | ativo |
| Lembretes | `/home/voide/Projetos/lembrete-bot` | agenda e notificações | pendente de token próprio |
| Kali legado | `/home/voide/Kali-Bunker-main` | polling antigo do painel remoto | desativado |

O Gmail central importa os componentes do Kali Bunker e usa o mesmo token do
serviço legado. Nunca ligue `gmail-telegram-bot.service` e
`kali-bunker-telegram.service` ao mesmo tempo.

As unidades operacionais dos três bots ficam em `~/.config/systemd/user`.
Cópias antigas no escopo de sistema estão inativas e desabilitadas; não as use.

## Pastas

- `Ativos/`: atalhos dos projetos atuais, mantidos por compatibilidade.
- `Arquivados/`: atalhos para backups reais; não contém o código canônico.
- `verificar.sh`: mostra arquivos, configuração, execução e autostart.
- `gerenciar.sh`: controla somente as quatro unidades conhecidas e bloqueia
  combinações conflitantes.

## Comandos

```bash
/home/voide/Bots/verificar.sh
/home/voide/Bots/gerenciar.sh status
/home/voide/Bots/gerenciar.sh gmail reiniciar
/home/voide/Bots/gerenciar.sh estudos logs 100
```

Use `ativar` para iniciar e habilitar no boot; use `desativar` para parar e
desabilitar. O gerenciador não inicia o Lembretes sem token e não permite ligar
o Kali legado enquanto o Gmail central estiver ativo ou habilitado.

## Segurança

- Tokens ficam somente nos arquivos `.env` com permissão `600`.
- Credenciais Google ficam em `gmail-telegram-bot/credentials/`, também `600`.
- Não cole tokens em documentação, comandos, commits ou conversas.
- Trabalhe nos projetos canônicos; não edite cópias de backup.

O alias `/home/voide/estudos-bot-main` foi preservado para o editor já
configurado, mas agora aponta diretamente para o projeto canônico de Estudos.
