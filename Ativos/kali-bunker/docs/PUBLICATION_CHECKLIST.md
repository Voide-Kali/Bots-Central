# Checklist antes de publicar

> Não torne o repositório público antes de decidir a estratégia de propriedade
> intelectual. Divulgação na internet pode afetar a novidade de uma possível
> patente. Esta orientação é geral e não substitui aconselhamento jurídico.

## Propriedade intelectual

- Registre autores, inventores, contribuições, contratos e titularidade.
- Faça busca de anterioridade e avalie se existe uma solução técnica com efeito
  técnico, não apenas uma ideia ou um programa de computador em si.
- Se houver matéria patenteável, deposite antes da divulgação pública.
- Considere também o registro de programa de computador no INPI.
- Escolha a licença somente depois de decidir o que será aberto e o que ficará
  privado como segredo empresarial.

Referências oficiais: [Lei 9.279/1996](https://www.planalto.gov.br/ccivil_03/leis/l9279.htm),
[Lei 9.609/1998](https://www.planalto.gov.br/ccivil_03/leis/l9609.htm) e
[condições importantes do INPI](https://www.gov.br/inpi/pt-br/servicos/patentes/tutorial-de-deposito/condicoes-importantes).

## Segurança e privacidade

- Rode `python scripts/prepublish_check.py --history`.
- Revise manualmente todo o histórico Git e todos os artefatos de release.
- Revogue e troque qualquer segredo que já tenha sido versionado; apagar o
  arquivo no commit atual não remove o histórico.
- Não publique `.env`, credenciais, tokens, bancos, logs, backups, fotos,
  endereços, MACs, e-mails reais nem arquivos do cofre.
- Mantenha terminal, exportação de arquivos, instalação de pacotes, webcam e
  cofre remotos desativados salvo necessidade explícita e análise de risco.
- Ative no GitHub o *secret scanning*, a *push protection*, o Dependabot e a
  configuração padrão do CodeQL.

## Validação técnica

```bash
python -m pytest -q
python -m compileall -q .
git diff --check
bash -n *.sh
```

Só publique depois de os testes passarem, o scanner não encontrar segredos e a
estratégia de propriedade intelectual estar definida.
