# Política de segurança

## Versões suportadas

Somente a versão mais recente da branch principal recebe correções de
segurança. Não exponha uma instalação do Kali Bunker diretamente à internet.

## Como relatar uma vulnerabilidade

Use um *Private Vulnerability Report* ou um *Security Advisory* privado do
GitHub. Não abra uma issue pública com tokens, chaves, dados pessoais, comandos
executáveis ou passos de exploração completos.

Inclua a versão, o componente afetado, o impacto e uma reprodução mínima sem
segredos reais. Revogue imediatamente qualquer credencial que possa ter sido
exposta.

## Modelo de segurança

- Recursos remotos sensíveis ficam desativados por padrão.
- A posse do token do Telegram deve ser tratada como acesso administrativo.
- Confirmação no mesmo chat não é um segundo fator de autenticação.
- O runtime de serviços privilegiados deve ser instalado em diretório
  controlado pelo `root`; nunca execute como `root` scripts editáveis na home.
- O manifesto SHA-256 detecta alteração do runtime por usuário sem privilégio e
  corrupção acidental. Ele não substitui inicialização verificada nem protege
  contra um invasor que já controla `root` e consegue trocar código e manifesto.
- `.env`, bancos, logs, estados, cofres, tokens OAuth e credenciais não fazem
  parte do repositório.

Antes de publicar ou implantar, execute os testes e siga
[`docs/PUBLICATION_CHECKLIST.md`](docs/PUBLICATION_CHECKLIST.md).
