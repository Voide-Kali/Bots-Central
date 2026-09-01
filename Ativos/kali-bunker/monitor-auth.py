#!/usr/bin/env python3
import subprocess
import time
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from notifier import alert_configured, alert_config_error, send_alert

COOLDOWN       = 15
ultimo_alerta  = 0
GEOLOCATION_ENABLED = 0
REMOTE_UNLOCK_MARKER = Path("/tmp/kali-bunker-remote-unlock-requested")
REMOTE_UNLOCK_IGNORE_SECONDS = 30
AUTH_PATTERNS = (
    re.compile(r"Failed password for (?P<usuario>\S+) from (?P<origem>\S+)"),
    re.compile(r"Invalid user (?P<usuario>\S+) from (?P<origem>\S+)"),
)


@dataclass
class AuthEvent:
    usuario: str
    origem: str
    linha: str


def find_auth_events(texto: str) -> list[AuthEvent]:
    eventos: list[AuthEvent] = []
    for linha in texto.splitlines():
        for pattern in AUTH_PATTERNS:
            match = pattern.search(linha)
            if match:
                eventos.append(
                    AuthEvent(
                        usuario=match.group("usuario"),
                        origem=match.group("origem"),
                        linha=linha,
                    )
                )
                break
    return eventos


def should_ignore_auth_event(evento: AuthEvent, now: float | None = None) -> bool:
    if evento.origem != "local/desconhecida":
        return False
    if "kde:auth" not in evento.linha and "kscreenlocker" not in evento.linha:
        return False
    try:
        marker = float(REMOTE_UNLOCK_MARKER.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    momento = time.time() if now is None else float(now)
    return momento - marker <= REMOTE_UNLOCK_IGNORE_SECONDS

def tirar_foto():
    foto = f"/tmp/intruso_{int(time.time())}.jpg"
    controls = (
        "brightness=146",
        "contrast=37",
        "backlight_compensation=2",
    )
    for control in controls:
        subprocess.run(["v4l2-ctl", "--set-ctrl", control], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(
        [
            "fswebcam", "--device", "/dev/video0", "--resolution", "1280x720",
            "--no-banner", "--skip", "30", "--frames", "5", "--jpeg", "95", foto,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if not os.path.exists(foto):
        return None
    try:
        import cv2
        import numpy as np
        img = cv2.imread(foto)
        if img is None:
            return foto
        img_yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        img_yuv[:,:,0] = cv2.equalizeHist(img_yuv[:,:,0])
        img = cv2.cvtColor(img_yuv, cv2.COLOR_YUV2BGR)
        kernel = np.array([[0,-1,0],[-1,5,-1],[0,-1,0]])
        img = cv2.filter2D(img, -1, kernel)
        cv2.imwrite(foto, img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    except Exception as exc:
        print(f"[WARN imagem] {exc}")
    return foto

def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "desconhecido"
    finally:
        sock.close()

def build_message(usuario):
    host = socket.gethostname()
    ip_local = get_local_ip()
    horario = time.strftime('%d/%m/%Y %H:%M:%S')
    return (
        "Senha errada!\n"
        f"Usuario: {usuario}\n"
        f"Host: {host}\n"
        f"IP local: {ip_local}\n"
        f"Horario: {horario}"
    )

def enviar_alerta(usuario, foto):
    if not alert_configured():
        print(f"[ERRO envio] {alert_config_error()}")
        return

    msg = build_message(usuario)
    if send_alert("TENTATIVA DE ACESSO!", msg, priority=1, sound="siren", photo_path=foto):
        if foto:
            Path(foto).unlink(missing_ok=True)

def get_cursor():
    r = subprocess.run(["journalctl","-n","0","--show-cursor","--no-pager"],
                       capture_output=True, text=True)
    for linha in (r.stdout + r.stderr).split("\n"):
        if "cursor:" in linha:
            return linha.split("cursor:")[-1].strip()
    return ""

def monitorar():
    global ultimo_alerta
    if not alert_configured():
        raise SystemExit(f"{alert_config_error()} Crie um .env baseado em .env.example.")

    print("Monitorando falhas de autenticacao...")
    cursor = get_cursor()

    while True:
        try:
            cmd = ["journalctl","--show-cursor","--no-pager","--output=short-monotonic"]
            if cursor:
                cmd.append(f"--after-cursor={cursor}")
            resultado = subprocess.run(cmd, capture_output=True, text=True)
            linhas = resultado.stdout

            for linha in (resultado.stdout + resultado.stderr).split("\n"):
                if "cursor:" in linha:
                    cursor = linha.split("cursor:")[-1].strip()

            if not linhas.strip():
                time.sleep(3)
                continue

            if re.search(r"FAILED SU|authentication failure|password check failed", linhas):
                agora = time.time()
                if agora - ultimo_alerta < COOLDOWN:
                    time.sleep(3)
                    continue
                usuario_match = re.search(r"user=(\w+)|user \((\w+)\)|FAILED SU \(to (\w+)\)", linhas)
                usuario = "desconhecido"
                if usuario_match:
                    usuario = next((g for g in usuario_match.groups() if g), "desconhecido")
                print(f"[ALERTA] Falha! Usuario: {usuario}")
                ultimo_alerta = agora
                foto = tirar_foto()
                enviar_alerta(usuario, foto)

        except Exception as e:
            print(f"[ERRO] {e}")

        time.sleep(3)

if __name__ == "__main__":
    monitorar()
