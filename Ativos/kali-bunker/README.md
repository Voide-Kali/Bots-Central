# 🛡️ Kali Linux Security Bunker

> Sistema de segurança e monitoramento em tempo real para Kali Linux, integrado com iPhone via Pushover.

![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![iPhone](https://img.shields.io/badge/iPhone-000000?style=for-the-badge&logo=apple&logoColor=white)

---

## 📋 Visão Geral

Este projeto transforma um **Galaxy Book 2** com Kali Linux em uma estação de trabalho monitorada 24/7, com alertas em tempo real no iPhone. Todos os eventos críticos — desde tentativas de invasão até o simples ato de ligar o computador — geram notificações instantâneas com som de sirene.

---

## 🚀 Funcionalidades

### 🔵 Alarme de Proximidade Bluetooth
- Monitora o sinal Bluetooth do iPhone a cada 3 segundos
- Quando o celular se afasta, dispara alarme no iPhone (5 minutos de sirene)
- Bloqueia a tela automaticamente após 10 segundos
- Bloqueia todas as portas USB contra pendrives desconhecidos
- Libera tudo automaticamente quando o iPhone volta

### 📸 Detector de Intrusos (Webcam)
- Monitora tentativas de senha errada em tempo real
- Tira foto automática pela webcam quando detecta falha de autenticação
- Envia a foto + localização GPS (por IP) para o iPhone via Pushover
- Processamento de imagem com OpenCV para melhor qualidade

### 🌐 Monitor de Rede WiFi
- Escaneia a rede local a cada 60 segundos com arp-scan
- Detecta dispositivos com MAC desconhecido
- Salva MACs conhecidos permanentemente em arquivo
- Alerta imediato no iPhone quando um intruso conecta na rede

### 🚫 Fail2Ban (Anti Força Bruta)
- Monitora tentativas de login SSH
- Bloqueia automaticamente IPs após 3 tentativas erradas
- Envia notificação no iPhone a cada banimento

### 📁 Monitor de Arquivos Sensíveis
- Vigia a pasta `/Documentos` em tempo real com inotify
- Alerta quando qualquer arquivo é acessado ou aberto
- Proteção contra bisbilhotagem de arquivos

### 📊 Monitor de CPU e RAM
- Verifica uso de recursos a cada 30 segundos
- Alerta quando CPU ultrapassa 80% ou RAM ultrapassa 85%
- Lista os processos mais pesados no momento do alerta

### 💡 Notificações de Boot e Shutdown
- Avisa no iPhone quando o computador é ligado (com IP e cidade)
- Avisa quando o computador é desligado

### 🧹 Manutenção Automática Semanal
- Todo domingo às 03:00: limpa cache, logs e lixeira
- Todo domingo às 09:00: envia relatório de saúde (RAM, CPU, Disco, Temperatura)

### 🖥️ Dashboard em Tempo Real
- Painel visual no terminal mostrando todos os serviços
- CPU, RAM, Disco, Temperatura e sinal Bluetooth do iPhone
- Status de todos os 11 serviços de segurança
- Top processos por consumo de CPU

### 🔍 Scanner de Rede
- Comando `scan-rede` para varreduras rápidas com nmap
- 4 modos: rápido, completo, hosts e UDP
- Salva relatório em `/Documentos` e notifica no iPhone

---

## 🛠️ Tecnologias Utilizadas

| Tecnologia | Uso |
|---|---|
| Python 3 | Scripts de monitoramento e alarmes |
| Bash | Scripts de manutenção e notificações |
| Systemd | Gerenciamento e persistência dos serviços |
| Pushover API | Notificações push no iPhone |
| BlueZ / hcitool | Monitoramento de sinal Bluetooth |
| OpenCV | Processamento de imagem da webcam |
| inotify-tools | Monitoramento de acesso a arquivos |
| arp-scan / nmap | Varredura de rede |
| Fail2Ban | Proteção contra ataques de força bruta |
| USBGuard | Bloqueio de dispositivos USB |
| Rich (Python) | Interface do dashboard no terminal |
| udev / v4l2 | Controle da webcam |

---

## 📁 Estrutura do Projeto

```
Kali-Bunker/
├── bluetooth_alarm.py      # Alarme de proximidade Bluetooth
├── monitor-auth.py         # Detector de intrusos com webcam
├── monitor-recursos.py     # Monitor de CPU e RAM
├── monitor-wifi.py         # Monitor de intrusos na rede WiFi
├── monitor-arquivos.sh     # Monitor de acesso a arquivos
├── relatorio-semanal.sh    # Relatório semanal de saúde
├── limpeza-semanal.sh      # Limpeza automática semanal
├── dashboard.py            # Dashboard visual no terminal
├── manual_seguranca_kali.pdf  # Manual completo do sistema
└── README.md
```

---

## ⚙️ Serviços Systemd

| Serviço | Tipo | Descrição |
|---|---|---|
| bt-alarm.service | Contínuo | Alarme Bluetooth |
| monitor-auth.service | Contínuo | Detector de intrusos |
| monitor-recursos.service | Contínuo | Monitor CPU/RAM |
| monitor-wifi.service | Contínuo | Monitor de rede |
| monitor-arquivos.service | Contínuo | Monitor de arquivos |
| usbguard.service | Contínuo | Bloqueio USB |
| fail2ban.service | Contínuo | Anti força bruta |
| notifica-boot.service | OneShot | Notificação de boot |
| notifica-shutdown.service | OneShot | Notificação de shutdown |
| limpeza-semanal.timer | Timer | Limpeza todo domingo 03:00 |
| relatorio-semanal.timer | Timer | Relatório todo domingo 09:00 |

---

## 🚀 Comandos do Dia a Dia

```bash
# Abrir o dashboard
dashboard

# Escanear a rede
scan-rede 192.168.3.0/24 hosts
scan-rede 192.168.3.1 full

# Ver status de todos os serviços
systemctl status bt-alarm monitor-auth monitor-recursos monitor-wifi

# Ver logs em tempo real
sudo journalctl -u bt-alarm -f

# Forçar limpeza semanal
sudo /usr/local/bin/limpeza-semanal.sh

# Forçar relatório semanal
sudo /usr/local/bin/relatorio-semanal.sh
```

---

## 🔒 Segurança

> ⚠️ Este repositório é **PRIVADO**. As chaves de API são carregadas de um arquivo `.env` local que **nunca é enviado ao GitHub**.

```bash
# Copie o exemplo e preencha seus dados
cp .env.example .env

# Estrutura do .env (não versionado)
ALERT_PROVIDER=telegram
TELEGRAM_BOT_TOKEN=seu_token_do_bot_aqui
TELEGRAM_CHAT_ID=seu_chat_id_aqui
IPHONE_MAC=XX:XX:XX:XX:XX:XX
```

Os scripts Python leem a configuração de `./.env` ou de `~/.config/kali-bunker/.env`.
Os scripts Bash usam o mesmo padrão via `bunker-env.sh`.

### Telegram Bot

1. Abra o Telegram e fale com `@BotFather`
2. Envie `/newbot`, escolha nome e usuario do bot
3. Copie o token para `TELEGRAM_BOT_TOKEN`
4. Mande qualquer mensagem para o seu bot
5. Acesse `https://api.telegram.org/botSEU_TOKEN/getUpdates`
6. Copie o numero de `chat.id` para `TELEGRAM_CHAT_ID`

Para testar:

```bash
python3 - <<'PY'
from notifier import send_alert
send_alert("TESTE KALI BUNKER", "Telegram configurado com sucesso.")
PY
```

### Dependências Python

```bash
python3 -m pip install -r requirements.txt
```

### Melhorias de robustez

- Credenciais removidas dos scripts e centralizadas no `.env`
- Alertas centralizados com suporte a Telegram Bot e Pushover
- MAC do iPhone configurável por `IPHONE_MAC`
- Interface WiFi configurável por `WIFI_INTERFACE`
- Chamadas de shell perigosas substituídas por `subprocess` com lista de argumentos
- Correção do envio de alerta sem foto no `monitor-auth.py`
- Validação clara quando as variáveis obrigatórias não estão configuradas

---

## 📱 Requisitos

- Kali Linux
- Telegram instalado no celular
- Bot do Telegram criado no BotFather
- Adaptador Bluetooth
- Webcam

### Agente do PC para o servidor

O arquivo `pc_agent.py` conecta este Kali ao painel que fica sempre ligado no
servidor. Ele informa telemetria e executa tarefas confirmadas de Nmap, SSH,
terminal, webcam e controle dos serviços. A unidade instalada é:

```bash
systemctl --user status kali-bunker-pc-agent.service
journalctl --user -u kali-bunker-pc-agent.service -f
```

As opções ficam em `~/.config/kali-bunker/pc-agent.env`; consulte
`pc-agent.env.example` para os nomes disponíveis.

---

*Desenvolvido por **voide** | 2026*
