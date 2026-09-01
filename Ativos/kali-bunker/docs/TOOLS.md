# Ferramentas do Kali Bunker

Este documento resume as ferramentas operacionais do Kali Bunker e como cada uma se encaixa no sistema.

## Operação

| Ferramenta | Entrada | Função |
|---|---|---|
| `bunkerctl` | `bunkerctl.py` | CLI principal para status, diagnóstico, reparo, backup, auditoria e relatórios |
| `kb` | `kb` | Atalho para todos os comandos de `bunkerctl.py` |
| `bunker-menu` | `bunker-menu` | Menu interativo para as operações mais usadas |
| `bunker-dashboard` | `dashboard.py` | Dashboard terminal em tempo real |
| `bunkerctl network` | `bunkerctl.py` | Estado, scan e aprendizado de dispositivos conhecidos |
| `bunkerctl ban` | `bunkerctl.py` | Lista e aplica bloqueios locais de IP/MAC suspeitos |
| Telegram remoto | `telegram_control.py` | Painel, serviços, rede, terminal, arquivos, IA e cofre pelo Telegram |

## Componentes do controle remoto

| Componente | Função |
|---|---|
| `telegram_control.py` | Interface Telegram opcional executada pelo serviço dedicado |
| `remote_control.py` | Conversa local/online, memória e planos de ação com confirmação |
| `voice_vault.py` | Cofre local criptografado; não registra a senha mestra |
| `state_utils.py` | Persistência JSON atômica para arquivos de estado |

## Sensores

| Ferramenta | Serviço | Função |
|---|---|---|
| Bluetooth alarm | `bt-alarm.service` | Monitora proximidade do iPhone e aciona bloqueio |
| Auth monitor | `monitor-auth.service` | Detecta falhas de autenticação e captura foto |
| Resource monitor | `monitor-recursos.service` | Acompanha CPU, RAM e processos pesados |
| Wi-Fi monitor | `monitor-wifi.service` | Detecta dispositivos desconhecidos na rede |
| Network watch | `network-watch.service` | Reaprende a rede quando SSID/gateway mudam |
| File monitor | `monitor-arquivos.service` | Monitora acessos a arquivos sensíveis |
| Telegram control | `kali-bunker-telegram.service` | Executa `telegram_control.py`; é opcional e desabilitado por padrão |

## Watchdog

| Ferramenta | Serviço | Função |
|---|---|---|
| Health monitor | `kali-bunker-health.service` | Supervisiona os módulos críticos, registra auditoria e alerta falhas |

## Manutenção

| Ferramenta | Timer | Função |
|---|---|---|
| Weekly cleanup | `limpeza-semanal.timer` | Limpeza semanal de pacotes e cache |
| Weekly report | `relatorio-semanal.timer` | Relatório semanal de saúde |

## Notificações

| Ferramenta | Serviço | Função |
|---|---|---|
| Boot alert | `notifica-boot.service` | Notifica quando o sistema inicia |
| Shutdown alert | `notifica-shutdown.service` | Notifica desligamento/reboot |

## Comandos úteis

```bash
kb quick
kb overview
bunker-menu
sudo kb up
sudo kb down
sudo kb restart
bunkerctl tools
bunkerctl status
bunkerctl doctor
bunkerctl repair
bunkerctl logs monitor-auth.service -n 100
bunkerctl audit -n 20
bunkerctl network status
bunkerctl network scan --unknown-only
bunkerctl network learn
bunkerctl ban scan
bunkerctl ban scan --unknown-only
sudo bunkerctl ban scan 192.168.3.0/24 --select 3 --apply
sudo bunkerctl ban add --ip 192.168.3.50 --reason "dispositivo desconhecido" --apply
bunkerctl ban list
bunkerctl report --format html -o relatorio.html
bunkerctl backup --keep 10
```

## Bloqueio de invasores

`bunkerctl network` mostra o estado de rede, escaneia dispositivos e aprende MACs confiáveis:

```bash
bunkerctl network status
bunkerctl network scan
bunkerctl network scan --unknown-only
bunkerctl network learn
bunkerctl network learn --replace
```

Use `network learn` em redes confiáveis para preencher `KNOWN_MACS_FILE` e evitar alerta repetido do `monitor-wifi.service`.

`bunkerctl ban` mantém uma lista local em `BANNED_DEVICES_FILE` e pode aplicar regras `iptables` contra IPs ou MACs.

O fluxo recomendado é:

```bash
bunkerctl ban scan 192.168.3.0/24 --unknown-only
sudo bunkerctl ban scan 192.168.3.0/24 --select 3 --apply
```

O primeiro comando lista os dispositivos encontrados pelo Nmap/ARP. O segundo registra e bloqueia localmente o dispositivo escolhido pelo número exibido na tabela. Quando o MAC aparece no scan, o Kali Bunker registra IP e MAC do alvo.

No Telegram, use:

```text
/status
/rede
/banip 192.168.3.50
/banmac AA:BB:CC:DD:EE:FF
/banidos
/cmd whoami
/arquivo ~/Documentos/arquivo.pdf
/ia me ajuda a estudar redes
/senhas
/pendentes
/confirmar ABC123
/cancelar ABC123
```

`/rede` detecta a rede atual pela rota padrão do PC, então funciona em redes diferentes sem fixar `192.168.3.0/24`.

Use `--apply` quando quiser aplicar ou remover as regras locais de firewall. Esse modo normalmente precisa ser executado como root.

Isso protege a máquina Kali Bunker contra o alvo. Para remover o dispositivo da rede inteira, bloqueie o MAC no roteador ou access point.
