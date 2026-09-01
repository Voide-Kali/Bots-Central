# Checklist antes de publicar

> Não torne o repositório público antes de decidir a estratégia de propriedade
> intelectual. Divulgação na internet pode afetar a novidade de uma possível
> patente. Esta orientação é geral e não substitui aconselhamento jurídico.

## Antes da abertura pública

- Documente autores, inventores, contribuições e titularidade.
- Faça busca de anterioridade e consulte um profissional sobre eventual
  solução técnica patenteável.
- Se houver matéria patenteável, deposite antes da divulgação.
- Considere o registro do programa de computador no INPI.
- Defina a licença somente depois de decidir o que será realmente aberto.

Referências oficiais: [Lei 9.279/1996](https://www.planalto.gov.br/ccivil_03/leis/l9279.htm),
[Lei 9.609/1998](https://www.planalto.gov.br/ccivil_03/leis/l9609.htm) e
[orientação do INPI](https://www.gov.br/inpi/pt-br/servicos/patentes/tutorial-de-deposito/condicoes-importantes).

## Segurança e privacidade

- Rode `python scripts/prepublish_check.py --history`.
- Confirme que `.env`, `config.py`, `credentials/`, tokens OAuth, banco SQLite,
  logs e conteúdo real de e-mails nunca foram rastreados.
- Se um segredo já entrou no Git, revogue-o antes de limpar o histórico.
- Use dados fictícios em exemplos e capturas de tela.
- Mantenha o resumo externo de e-mails desligado até haver consentimento e uma
  avaliação do tratamento de dados.
- Ative no GitHub o *secret scanning*, a *push protection*, o Dependabot e a
  configuração padrão do CodeQL.

## Validação

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
git diff --check
```
