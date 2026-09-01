#!/usr/bin/env python3
import subprocess
import time
import os
import re
import json
import urllib.request

def load_env():
    env = {}
    with open("/home/voide/.env") as f:
        for line in f:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                env[k] = v
    return env
ENV = load_env()
PUSHOVER_TOKEN = ENV["PUSHOVER_TOKEN"]
PUSHOVER_USER  = "u2qzmnz761dxbrs3b3y14i143j7v61"
COOLDOWN       = 15
ultimo_alerta  = 0

def tirar_foto():
    foto = f"/tmp/intruso_{int(time.time())}.jpg"
    os.system("v4l2-ctl --set-ctrl brightness=146 2>/dev/null")
    os.system("v4l2-ctl --set-ctrl contrast=37 2>/dev/null")
    os.system("v4l2-ctl --set-ctrl backlight_compensation=2 2>/dev/null")
    os.system(f"fswebcam --device /dev/video0 --resolution 1280x720 --no-banner --skip 30 --frames 5 --jpeg 95 {foto} 2>/dev/null")
    if not os.path.exists(foto):
        return None
    try:
        import cv2
        import numpy as np
        img = cv2.imread(foto)
        img_yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
        img_yuv[:,:,0] = cv2.equalizeHist(img_yuv[:,:,0])
        img = cv2.cvtColor(img_yuv, cv2.COLOR_YUV2BGR)
        kernel = np.array([[0,-1,0],[-1,5,-1],[0,-1,0]])
        img = cv2.filter2D(img, -1, kernel)
        cv2.imwrite(foto, img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    except:
        pass
    return foto

def enviar_alerta(usuario, foto):
    try:
        loc = json.loads(urllib.request.urlopen("http://ip-api.com/json", timeout=5).read())
        ip     = loc.get("query", "")
        cidade = loc.get("city", "")
        lat    = loc.get("lat", "")
        lon    = loc.get("lon", "")
    except:
        ip = cidade = lat = lon = ""

    msg = f"Senha errada!\nUsuario: {usuario}\nIP: {ip}\nCidade: {cidade}\nHorario: {time.strftime('%d/%m/%Y %H:%M:%S')}"

    try:
        if foto and os.path.exists(foto):
            with open(foto, "rb") as f:
                foto_bytes = f.read()
            boundary = "boundary123"
            body = b""
            campos = {
                "token": PUSHOVER_TOKEN, "user": PUSHOVER_USER,
                "title": "TENTATIVA DE ACESSO!", "message": msg,
                "priority": "1", "sound": "siren"
            }
            if lat and lon:
                campos["url"] = f"https://maps.google.com/?q={lat},{lon}"
                campos["url_title"] = "Ver no mapa"
            for k, v in campos.items():
                body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
            body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"foto.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n".encode()
            body += foto_bytes + f"\r\n--{boundary}--\r\n".encode()
            req = urllib.request.Request(
                "https://api.pushover.net/1/messages.json", data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
            urllib.request.urlopen(req, timeout=10)
            os.remove(foto)
        else:
            urllib.request.urlopen(
                urllib.request.Request(
                    "https://api.pushover.net/1/messages.json",
                    data=urllib.parse.urlencode({
                        "token": PUSHOVER_TOKEN, "user": PUSHOVER_USER,
                        "title": "TENTATIVA DE ACESSO!", "message": msg,
                        "priority": "1", "sound": "siren"
                    }).encode()),
                timeout=10)
    except Exception as e:
        print(f"[ERRO envio] {e}")

def get_cursor():
    r = subprocess.run(["journalctl","-n","0","--show-cursor","--no-pager"],
                       capture_output=True, text=True)
    for linha in (r.stdout + r.stderr).split("\n"):
        if "cursor:" in linha:
            return linha.split("cursor:")[-1].strip()
    return ""

def monitorar():
    global ultimo_alerta
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

monitorar()
