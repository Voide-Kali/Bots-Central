#!/usr/bin/env python3
import psutil
import requests
import time

PUSHOVER_TOKEN = open("/home/voide/.env").read().split("PUSHOVER_TOKEN=")[1].split("\n")[0]
PUSHOVER_USER = open("/home/voide/.env").read().split("PUSHOVER_USER=")[1].split("\n")[0]

LIMITE_CPU     = 80
LIMITE_RAM     = 85
INTERVALO      = 30
COOLDOWN       = 300

ultimo_alerta_cpu = 0
ultimo_alerta_ram = 0

def top_processos_cpu():
    procs = []
    for p in psutil.process_iter(['name', 'cpu_percent']):
        try:
            procs.append(p.info)
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
    try:
        requests.post("https://api.pushover.net/1/messages.json", data={
            "token": PUSHOVER_TOKEN,
            "user": PUSHOVER_USER,
            "title": titulo,
            "message": mensagem,
            "priority": 1,
            "sound": "siren"
        }, timeout=5)
    except Exception as e:
        print(f"[ERRO] {e}")

def main():
    global ultimo_alerta_cpu, ultimo_alerta_ram
    print("Monitorando CPU e RAM...")
    psutil.cpu_percent(interval=1)

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

main()
