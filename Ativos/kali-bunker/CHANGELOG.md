# Changelog

## Unreleased

- adiciona catálogo profissional de ferramentas com `bunkerctl tools`
- adiciona bloqueio defensivo local com `bunkerctl ban`
- adiciona fluxo `bunkerctl ban scan` para escanear a rede e escolher o dispositivo a bloquear
- melhora a integração instalada do `bunkerctl ban scan` com dependências, usuário operacional e permissões
- adiciona controle de rede pelo Telegram com `/rede`, `/banip`, `/banmac` e `/banidos`
- melhora a detecção automática da rede atual usando a rota padrão do PC
- adiciona documentação `docs/TOOLS.md`
- melhora a saída do instalador `install.sh`
- adiciona `bunkerctl repair` e `bunkerctl doctor --fix`
- adiciona `bunkerctl backup` com `.env` redigido por padrão
- adiciona rotação de backups com `bunkerctl backup --keep`
- adiciona `bunkerctl report` em texto, JSON e HTML
- adiciona checklist pós-instalação com `bunkerctl install-check`
- adiciona exportação de auditoria em JSON, JSONL e CSV
- organiza a documentação principal do Kali Bunker
- adiciona `.gitignore` para arquivos locais e de runtime
- padroniza a seção de organização do repositório
