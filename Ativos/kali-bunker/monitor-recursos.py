#!/usr/bin/env python3
import psutil
import time
from bunker_config import get_int
from notifier import alert_configured, alert_config_error, send_alert

LIMITE_CPU     = get_int("LIMITE_CPU", 80)
LIMITE_RAM     = get_int("LIMITE_RAM", 85)
INTERVALO      = get_int("INTERVALO_RECURSOS", 30)
COOLDOWN       = get_int("COOLDOWN_RECURSOS", 300)

ultimo_alerta_cpu = 0
ultimo_alerta_ram = 0

def top_processos_cpu():
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent']):
        try:
            procs.append({"name": p.info.get("name") or "?", "cpu_percent": p.cpu_percent(interval=None)})
        except:
            pass
    procs = sorted(procs, key=lambda p: p['cpu_percent'], reverse=True)
    return "\n".join([f"  {p['name']}: {p['cpu_percent']:.1f}%" for p in procs[:5]])

def top_processos_ram():
    procs = []
    for p in psutil.process_iter(['name', 'memory_percent']):
        try:
            procs.append(p.info)
        except:
            pass
    procs = sorted(procs, key=lambda p: p['memory_percent'], reverse=True)
    return "\n".join([f"  {p['name']}: {p['memory_percent']:.1f}%" for p in procs[:5]])

def enviar_alerta(titulo, mensagem):
    send_alert(titulo, mensagem, priority=1, sound="siren")

def main():
    global ultimo_alerta_cpu, ultimo_alerta_ram
    if not alert_configured():
        raise SystemExit(f"{alert_config_error()} Crie um .env baseado em .env.example.")

    print("Monitorando CPU e RAM...")
    psutil.cpu_percent(interval=1)
    # Prime o calculo de CPU por processo (psutil usa delta entre chamadas).
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    while True:
        try:
            cpu = psutil.cpu_percent(interval=5)
            ram = psutil.virtual_memory().percent
            agora = time.time()

            print(f"CPU: {cpu}% | RAM: {ram}%")

            if cpu >= LIMITE_CPU and (agora - ultimo_alerta_cpu) > COOLDOWN:
                tops = top_processos_cpu()
                enviar_alerta("CPU ALTA!", f"CPU em {cpu}%\n\nTop processos:\n{tops}")
                ultimo_alerta_cpu = agora

            if ram >= LIMITE_RAM and (agora - ultimo_alerta_ram) > COOLDOWN:
                tops = top_processos_ram()
                enviar_alerta("RAM ALTA!", f"RAM em {ram}%\n\nTop processos:\n{tops}")
                ultimo_alerta_ram = agora

            time.sleep(INTERVALO)

        except Exception as e:
            print(f"[ERRO] {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
