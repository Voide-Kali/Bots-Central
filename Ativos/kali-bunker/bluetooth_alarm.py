#!/usr/bin/env python3
import subprocess
import time
from bunker_config import IPHONE_MAC, USERNAME, get_int
from notifier import alert_configured, alert_config_error, send_alert

RSSI_LIMITE    = get_int("RSSI_LIMITE", -70)
INTERVALO      = get_int("INTERVALO_BLUETOOTH", 3)
FALHAS_MAX     = get_int("FALHAS_MAX", 12)
DELAY_BLOQUEIO = get_int("DELAY_BLOQUEIO", 10)

def get_session_id():
    try:
        result = subprocess.run(["loginctl","list-sessions","--no-legend"],
                                capture_output=True, text=True)
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[2] == USERNAME and parts[3] == "seat0":
                return parts[0]
        # Fallback: retorna a primeira sessao do usuario (caso seat nao seja seat0)
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[2] == USERNAME:
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
    try:
        subprocess.run(["sudo","usbguard","set-parameter",
                        "ImplicitPolicyTarget","block"], capture_output=True)
        print("[USB] Bloqueado!")
    except Exception as e:
        print(f"[ERRO USB] {e}")

def liberar_usb():
    try:
        subprocess.run(["sudo","usbguard","set-parameter",
                        "ImplicitPolicyTarget","allow"], capture_output=True)
        print("[USB] Liberado!")
    except Exception as e:
        print(f"[ERRO USB] {e}")

def bloquear_tela():
    try:
        session = get_session_id()
        if session:
            print(f"[TELA] Bloqueando em {DELAY_BLOQUEIO}s...")
            time.sleep(DELAY_BLOQUEIO)
            subprocess.run(["loginctl", "lock-session", session], check=False)
            print("[TELA] Bloqueada!")
    except Exception as e:
        print(f"[ERRO tela] {e}")

def enviar_alarme():
    if alert_configured():
        send_alert(
            "ALARME DE PROXIMIDADE",
            "iPhone longe! Tela e USB bloqueados em 10 segundos.",
            priority=2,
            sound="siren",
        )
        print("[ALARME] Enviado!")
    else:
        print(f"[ERRO] {alert_config_error()}")
    bloquear_usb()
    bloquear_tela()

def enviar_ok():
    if alert_configured():
        send_alert(
            "iPhone voltou!",
            "Proximidade restaurada. Tela e USB liberados.",
            priority=-1,
            sound="none",
        )
        print("[OK] iPhone voltou.")
    liberar_usb()

def main():
    if not IPHONE_MAC:
        raise SystemExit("IPHONE_MAC nao configurado. Crie um .env baseado em .env.example.")

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

if __name__ == "__main__":
    main()
