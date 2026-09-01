# Contributing

## Scope

Este repositório é organizado para segurança local, automação e alertas.
Mudanças pequenas e focadas são preferíveis.

## Antes de abrir PR

- rode `bunkerctl doctor`
- rode a suíte de testes quando houver alteração em código Python
- verifique `git diff --check`
- não comite `.env`, credenciais ou arquivos de runtime

## Estilo

- mantenha os scripts curtos e legíveis
- preserve a compatibilidade com `systemd`
- mantenha o `README` alinhado com os comandos reais

