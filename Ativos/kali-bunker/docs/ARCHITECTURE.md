# Arquitetura do Kali Bunker

## Camadas

1. **Sensores**
   - autenticação, Bluetooth, Wi-Fi, arquivos e recursos;
2. **Notificação**
   - Telegram ou Pushover por meio de `notifier.py`;
3. **Operação**
   - `bunkerctl`, dashboard, relatórios, backup e reparos;
4. **Autovigilância**
   - `health_monitor.py` verifica os próprios serviços e detecta recuperação;
5. **Auditoria**
   - eventos estruturados em
     `~/.local/state/kali-bunker/audit.jsonl`.

## Estado local

Arquivos de runtime ficam em `~/.local/state/kali-bunker`:

- `audit.jsonl`: entregas de alertas e transições do watchdog;
- `health-latest.json`: último retrato completo do sistema;
- `health-state.json`: debounce, cooldown e falhas já notificadas.
- `backups/`: pacotes criados por `bunkerctl backup`.

Nenhuma credencial é gravada nesses arquivos.

## Instalação protegida

`install.sh` separa fonte e runtime: o repositório continua editável pelo
usuário, enquanto os serviços de sistema executam a cópia `root:root` em
`/opt/kali-bunker` e o Python do ambiente virtual desse runtime. A configuração
de sistema é uma cópia `600` em `/etc/kali-bunker/kali-bunker.env`. Assim, um
serviço privilegiado não executa código ou configuração alterável por usuário
sem uma nova instalação explícita.

A atualização do runtime usa uma área de preparação no mesmo sistema de
arquivos. Depois de copiar o código, instalar as dependências e renderizar as
unidades, o instalador gera um manifesto SHA-256 para a lista canônica de código,
scripts, requisitos e unidades systemd e promove o diretório preparado. A versão
anterior fica disponível como `.kali-bunker.previous`. O `.env`, outros segredos,
o ambiente virtual e o próprio manifesto são excluídos da lista de hashes.
`bunker_health.py` valida conteúdo, ausência, tipo, proprietário e permissões; o
resultado aparece no `status`, no monitor de saúde e no `doctor` sem expor dados
dos arquivos.

## Fluxo de falha

```text
serviço falha
  → watchdog confirma em duas verificações
  → registra evento local
  → envia alerta
  → aplica cooldown
  → detecta recuperação
  → envia confirmação de normalização
```

## Princípios

- configuração fora do código;
- falha de auditoria nunca interrompe alertas;
- escrita atômica de estado;
- serviços com reinício controlado;
- diagnóstico legível por humanos e JSON para automação;
- permissões restritivas para credenciais e estado.

## Operação com bunkerctl

- `bunkerctl doctor --fix` executa diagnóstico e tenta reparos seguros;
- `bunkerctl repair` mostra os reparos sugeridos sem executar;
- `bunkerctl repair --apply` aplica criação de diretórios, permissões e reinício de serviços críticos;
- `bunkerctl backup` cria um pacote local com `.env` redigido, units systemd e estado;
- `bunkerctl backup --keep N` remove backups antigos e mantém os N mais recentes;
- `bunkerctl report --format text|json|html` gera relatórios operacionais;
- `bunkerctl install-check` mostra o checklist pós-instalação;
- `bunkerctl audit --export csv|json|jsonl` exporta a trilha de auditoria.
