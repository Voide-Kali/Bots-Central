#!/usr/bin/env python3
import subprocess
import time
import requests
import os

# Carrega as chaves do arquivo .env
def load_env():
    env = {}
    with open("/home/voide/.env") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                env[k] = v
    return env

ENV = load_env()
IPHONE_MAC     = ENV["IPHONE_MAC"]
PUSHOVER_USER  = ENV["PUSHOVER_USER"]
PUSHOVER_TOKEN = ENV["PUSHOVER_TOKEN"]
RSSI_LIMITE    = -70
INTERVALO      = 3
FALHAS_MAX     = 12
DELAY_BLOQUEIO = 10

def get_session_id():
    try:
        result = subprocess.run(["loginctl","list-sessions","--no-legend"],
                                capture_output=True, text=True)
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[2]=="voide" and parts[3]=="seat0":
                return parts[0]
    except:
        pass
    return None

def get_rssi(mac):
    try:
        r = subprocess.run(["hcitool","rssi",mac],
                           capture_output=True, text=True, timeout=5)
        if r.returncode==0 and "RSSI return value:" in r.stdout:
            return int(r.stdout.strip().split(":")[-1].strip())
    except:
        pass
    return None

def bloquear_usb():
    subprocess.run(["sudo","usbguard","set-parameter",
                    "ImplicitPolicyTarget","block"], capture_output=True)
    print("[USB] Bloqueado!")

def liberar_usb():
    subprocess.run(["sudo","usbguard","set-parameter",
                    "ImplicitPolicyTarget","allow"], capture_output=True)
    print("[USB] Liberado!")

def bloquear_tela():
    session = get_session_id()
    if session:
        print(f"[TELA] Bloqueando em {DELAY_BLOQUEIO}s...")
        time.sleep(DELAY_BLOQUEIO)
        os.system(f"loginctl lock-session {session}")
        print("[TELA] Bloqueada!")

def enviar_alarme():
    try:
        requests.post("https://api.pushover.net/1/messages.json", data={
            "token": PUSHOVER_TOKEN, "user": PUSHOVER_USER,
            "title": "ALARME DE PROXIMIDADE",
            "message": "iPhone longe! Tela e USB bloqueados.",
            "priority": 2, "retry": 30, "expire": 300, "sound": "siren"
        }, timeout=5)
        print("[ALARME] Enviado!")
    except Exception as e:
        print(f"[ERRO] {e}")
    bloquear_usb()
    bloquear_tela()

def enviar_ok():
    try:
        requests.post("https://api.pushover.net/1/messages.json", data={
            "token": PUSHOVER_TOKEN, "user": PUSHOVER_USER,
            "title": "iPhone voltou!",
            "message": "Proximidade restaurada. Tela e USB liberados.",
            "priority": -1, "sound": "none"
        }, timeout=5)
        print("[OK] iPhone voltou.")
    except:
        pass
    liberar_usb()

def main():
    print(f"Monitorando iPhone [{IPHONE_MAC}]")
    falhas = 0
    alarme_ativo = False
    while True:
        rssi = get_rssi(IPHONE_MAC)
        if rssi is None:
            falhas += 1
            print(f"[{time.strftime('%H:%M:%S')}] Sem sinal (falha {falhas}/{FALHAS_MAX})")
        elif rssi < RSSI_LIMITE:
            falhas += 1
            print(f"[{time.strftime('%H:%M:%S')}] RSSI fraco: {rssi} dBm (falha {falhas}/{FALHAS_MAX})")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] RSSI: {rssi} dBm OK")
            if alarme_ativo:
                enviar_ok()
                alarme_ativo = False
            falhas = 0
        if falhas >= FALHAS_MAX and not alarme_ativo:
            enviar_alarme()
            alarme_ativo = True
        time.sleep(INTERVALO)

main()
