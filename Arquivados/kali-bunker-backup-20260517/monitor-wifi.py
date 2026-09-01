import os
import time
import subprocess

USER_KEY = "u2qzmnz761dxbrs3b3y14i143j7v61"
API_TOKEN = "agjsv1wivgccbqmvmjwb69d6hf4k1j"
KNOWN_MACS_FILE = "/home/voide/macs_conhecidos.txt"

# MACs que NUNCA devem disparar alerta (ex: seu PC, roteador)
ALLOWED_MACS = ["6C:F6:DA:EF:EF:16", "00:00:00:00:00:00"]

def send_pushover(message):
    cmd = f'curl -s -F "token={API_TOKEN}" -F "user={USER_KEY}" -F "title=🚨 INVASOR WIFI" -F "message={message}" -F "sound=siren" https://api.pushover.net/1/messages.json'
    os.system(cmd)

def get_saved_macs():
    if not os.path.exists(KNOWN_MACS_FILE): return set()
    with open(KNOWN_MACS_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def save_mac(mac):
    with open(KNOWN_MACS_FILE, "a") as f:
        f.write(mac + "\n")

print("[+] Monitor de WiFi Permanente Iniciado...")
known_devices = get_saved_macs() | set(ALLOWED_MACS)

while True:
    output = subprocess.check_output("sudo arp-scan --interface=wlan0 --localnet --ignoredups", shell=True).decode()
    for line in output.splitlines():
        if "6C:F6" in line or ".:" in line: # Filtra linhas com endereços MAC
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1].upper()
                if mac not in known_devices:
                    send_pushover(f"Novo dispositivo detectado!\nIP: {ip}\nMAC: {mac}")
                    known_devices.add(mac)
                    save_mac(mac)
    time.sleep(60)
