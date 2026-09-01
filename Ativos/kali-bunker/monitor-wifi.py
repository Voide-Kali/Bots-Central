#!/usr/bin/env python3
import os
import time
import subprocess
import re
from bunker_config import KNOWN_MACS_FILE, WIFI_INTERFACE
from notifier import alert_configured, alert_config_error, send_alert

# MACs que NUNCA devem disparar alerta (ex: seu PC, roteador)
ALLOWED_MACS = [
    mac.strip().upper()
    for mac in os.environ.get("ALLOWED_MACS", "6C:F6:DA:EF:EF:16,00:00:00:00:00:00").split(",")
    if mac.strip()
]
MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
ARP_SCAN_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>(?:[0-9A-F]{2}:){5}[0-9A-F]{2})\s+"
)
SCAN_INTERVAL_SECONDS = max(10, int(os.environ.get("WIFI_SCAN_INTERVAL_SECONDS", "60")))
MAX_ALERTS_PER_SCAN = max(1, int(os.environ.get("WIFI_MAX_ALERTS_PER_SCAN", "5")))
SUMMARY_COOLDOWN_SECONDS = max(60, int(os.environ.get("WIFI_SUMMARY_COOLDOWN_SECONDS", "900")))
ENTERPRISE_NEW_DEVICE_THRESHOLD = max(1, int(os.environ.get("WIFI_ENTERPRISE_NEW_DEVICE_THRESHOLD", "8")))
TRUSTED_SSIDS = {
    ssid.strip().lower()
    for ssid in os.environ.get("WIFI_TRUSTED_SSIDS", "").split(",")
    if ssid.strip()
}
LEARN_ON_TRUSTED_SSID = os.environ.get("WIFI_LEARN_ON_TRUSTED_SSID", "1") != "0"
ALERT_PRIVATE_MACS = os.environ.get("WIFI_ALERT_PRIVATE_MACS", "0") == "1"
last_summary_alert_at = 0.0

def valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            val = int(part)
        except ValueError:
            return False
        if val < 0 or val > 255:
            return False
    return True

def parse_scan_line(line):
    match = ARP_SCAN_RE.match(line.strip())
    if not match:
        return None
    ip = match.group("ip")
    if not valid_ip(ip):
        return None
    mac = match.group("mac").upper()
    if not MAC_RE.match(mac):
        return None
    return ip, mac

def is_private_mac(mac: str) -> bool:
    first_octet = int(mac.split(":", 1)[0], 16)
    return bool(first_octet & 0b10)

def current_ssid() -> str:
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for line in result.stdout.splitlines():
        if line.startswith("yes:"):
            return line.split(":", 1)[1].strip()
    return ""

def should_learn_without_alert(ssid: str) -> bool:
    return LEARN_ON_TRUSTED_SSID and ssid.strip().lower() in TRUSTED_SSIDS

def get_saved_macs():
    if not os.path.exists(KNOWN_MACS_FILE): return set()
    with open(KNOWN_MACS_FILE, "r") as f:
        return set(line.strip().upper() for line in f if line.strip())

def save_mac(mac):
    macs_dir = os.path.dirname(KNOWN_MACS_FILE)
    if macs_dir:
        os.makedirs(macs_dir, exist_ok=True)
    with open(KNOWN_MACS_FILE, "a") as f:
        f.write(mac + "\n")

def scan_network():
    result = subprocess.run(
        ["sudo", "arp-scan", f"--interface={WIFI_INTERFACE}", "--localnet", "--ignoredups"],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if result.returncode != 0:
        print(f"[ERRO arp-scan] {result.stderr.strip()}")
    return result.stdout

def main():
    if not alert_configured():
        raise SystemExit(f"{alert_config_error()} Crie um .env baseado em .env.example.")

    print("[+] Monitor de WiFi Permanente Iniciado...")
    known_devices = get_saved_macs() | set(ALLOWED_MACS)
    global last_summary_alert_at

    while True:
        try:
            output = scan_network()
        except Exception as exc:
            print(f"[ERRO scan] {exc}")
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        ssid = current_ssid()
        new_devices = []
        for line in output.splitlines():
            parsed = parse_scan_line(line)
            if not parsed:
                continue
            ip, mac = parsed
            if mac not in known_devices:
                new_devices.append((ip, mac))

        if not new_devices:
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        for _ip, mac in new_devices:
            known_devices.add(mac)
            save_mac(mac)

        if should_learn_without_alert(ssid):
            print(f"[wifi] {len(new_devices)} novos dispositivos aprendidos em SSID confiavel: {ssid}")
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        public_devices = [(ip, mac) for ip, mac in new_devices if ALERT_PRIVATE_MACS or not is_private_mac(mac)]
        if not public_devices:
            print(f"[wifi] {len(new_devices)} dispositivos com MAC privado aprendidos sem alerta.")
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        now = time.time()
        if len(new_devices) >= ENTERPRISE_NEW_DEVICE_THRESHOLD:
            if now - last_summary_alert_at >= SUMMARY_COOLDOWN_SECONDS:
                sample = "\n".join(f"- {ip} {mac}" for ip, mac in public_devices[:MAX_ALERTS_PER_SCAN])
                hidden = max(0, len(public_devices) - MAX_ALERTS_PER_SCAN)
                suffix = f"\n... e mais {hidden} dispositivo(s)." if hidden else ""
                send_alert(
                    "REDE WIFI MOVIMENTADA",
                    (
                        f"{len(new_devices)} novos dispositivos detectados em uma varredura."
                        f"\nSSID: {ssid or 'N/D'}"
                        "\nTratado como rede movimentada/corporativa para evitar flood."
                        f"\n{sample}{suffix}"
                    ),
                    sound=None,
                )
                last_summary_alert_at = now
            else:
                print(f"[wifi] Resumo suprimido por cooldown: {len(new_devices)} novos dispositivos.")
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        for ip, mac in public_devices[:MAX_ALERTS_PER_SCAN]:
            send_alert("INVASOR WIFI", f"Novo dispositivo detectado!\nIP: {ip}\nMAC: {mac}", sound="siren")
        time.sleep(SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
