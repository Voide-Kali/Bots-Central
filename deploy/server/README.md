# Deploy rápido do Bots-Central

Esta pasta prepara um deploy reproduzível do commit validado, sem copiar arquivos
não rastreados, secrets ou alterações locais.

## Fluxo

No clone validado:

```bash
EXPECTED_SHA=<sha-verde> bash deploy/server/preflight.sh
sudo EXPECTED_SHA=<sha-verde> bash deploy/server/install.sh
sudoedit /etc/bots-central/bots-central.env
sudoedit /etc/bots-central/studies.env
sudoedit /etc/bots-central/gmail-config.py
sudoedit /etc/bots-central/studies-config.py
sudo bash deploy/server/activate.sh
sudo bash deploy/server/verify.sh
```

O instalador usa `git archive` do SHA informado. Portanto um working tree sujo
não entra silenciosamente em produção.

## Layout

- Código versionado: `/opt/bots-central/releases/<sha>`
- Release ativa: `/opt/bots-central/current`
- Venv Gmail/central: `/opt/bots-central/venvs/gmail`
- Venv Estudos: `/opt/bots-central/venvs/studies`
- Configuração/credenciais: `/etc/bots-central`
- Estado persistente: `/var/lib/bots-central`

Gmail e Estudos usam venvs separados porque as versões atuais de
`python-telegram-bot` e `python-dotenv` ainda não são unificadas.

## Regra do Telegram

Enquanto Central e Estudos forem processos de long polling separados, use tokens
de bots diferentes. O preflight bloqueia ativação se detectar o mesmo token nos
dois ambientes.

## Rollback

A release anterior permanece em `/opt/bots-central/releases`. Para voltar:

```bash
sudo ln -sfn /opt/bots-central/releases/<sha-anterior> /opt/bots-central/current
sudo systemctl restart bots-central.service bots-central-studies.service
```

Não apague releases anteriores até validar o novo deploy.
