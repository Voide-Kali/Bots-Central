# Política de segurança

## Como relatar

Use um *Private Vulnerability Report* ou um *Security Advisory* privado do
GitHub. Não publique tokens, credenciais OAuth, conteúdo de e-mail, dados
pessoais ou passos completos de exploração em uma issue pública.

Revogue imediatamente qualquer credencial possivelmente exposta.

## Modelo de segurança

- O bot deve aceitar comandos somente do chat e do usuário autorizados.
- Resumo externo de e-mail e ações remotas sensíveis ficam desativados por
  padrão e exigem ativação consciente.
- `.env`, `config.py`, bancos e a pasta `credentials/` nunca devem ser
  versionados.
- O token do Telegram e os tokens OAuth do Gmail concedem acesso sensível; não
  os reutilize em ambientes não confiáveis.

Antes de publicar, siga
[`docs/PUBLICATION_CHECKLIST.md`](docs/PUBLICATION_CHECKLIST.md).
