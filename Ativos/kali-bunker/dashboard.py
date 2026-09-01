#!/usr/bin/env python3
import psutil
import subprocess
import threading
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from datetime import datetime
from bunker_config import IPHONE_MAC

console = Console()
_snapshot_lock = threading.Lock()
_snapshot = None

def get_service_status(unit):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=3
        )
        status = result.stdout.strip()
        if status == "active":
            return "[green]● ATIVO[/green]"
        elif status == "inactive":
            return "[yellow]● STANDBY[/yellow]"
        else:
            return "[red]● ERRO[/red]"
    except:
        return "[red]● ERRO[/red]"

def get_rssi(mac):
    if not mac:
        return "[white]📵 IPHONE_MAC nao configurado[/white]"
    try:
        result = subprocess.run(
            ["hcitool", "rssi", mac],
            capture_output=True, text=True, timeout=3
        )
        if "RSSI return value:" in result.stdout:
            rssi = int(result.stdout.strip().split(":")[-1].strip())
            if rssi > -50:
                return f"[green]📶 {rssi} dBm (Perto)[/green]"
            elif rssi > -70:
                return f"[yellow]📶 {rssi} dBm (Médio)[/yellow]"
            else:
                return f"[red]📶 {rssi} dBm (Longe)[/red]"
    except:
        pass
    return "[red]📵 Sem sinal[/red]"

def get_temp():
    try:
        result = subprocess.run(["sensors"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "Package id 0" in line:
                temp = line.split(":")[1].strip().split(" ")[0]
                val = float(temp.replace("+","").replace("°C",""))
                if val < 60:
                    return f"[green]🌡️  {temp}[/green]"
                elif val < 80:
                    return f"[yellow]🌡️  {temp}[/yellow]"
                else:
                    return f"[red]🌡️  {temp}[/red]"
    except:
        pass
    return "[white]🌡️  N/A[/white]"

def make_dashboard():
    now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    cpu_color = "green" if cpu < 60 else "yellow" if cpu < 80 else "red"
    ram_color = "green" if ram.percent < 70 else "yellow" if ram.percent < 85 else "red"
    disk_color = "green" if disk.percent < 70 else "yellow" if disk.percent < 85 else "red"

    recursos = Table(title="💻 RECURSOS DO SISTEMA", border_style="blue", expand=True)
    recursos.add_column("Componente", style="bold white")
    recursos.add_column("Uso", justify="right")
    recursos.add_column("Detalhes", justify="right")

    recursos.add_row("CPU", f"[{cpu_color}]{cpu:.1f}%[/{cpu_color}]", f"{psutil.cpu_count()} núcleos")
    recursos.add_row("RAM", f"[{ram_color}]{ram.percent:.1f}%[/{ram_color}]", f"{ram.used//1024//1024}MB / {ram.total//1024//1024}MB")
    recursos.add_row("Disco", f"[{disk_color}]{disk.percent:.1f}%[/{disk_color}]", f"{disk.used//1024//1024//1024}GB / {disk.total//1024//1024//1024}GB")
    recursos.add_row("Temperatura", get_temp(), "")
    recursos.add_row("iPhone", get_rssi(IPHONE_MAC), "Bluetooth")

    servicos = Table(title="🛡️ SERVIÇOS DE SEGURANÇA", border_style="red", expand=True)
    servicos.add_column("Serviço", style="bold white")
    servicos.add_column("Status", justify="center")
    servicos.add_column("Tipo", justify="center", style="dim")

    services = [
        ("bt-alarm.service",          "🔵 Alarme Bluetooth",   "Contínuo"),
        ("monitor-auth.service",      "📸 Monitor de Acesso",  "Contínuo"),
        ("monitor-recursos.service",  "📊 Monitor CPU/RAM",    "Contínuo"),
        ("monitor-wifi.service",      "🌐 Monitor WiFi",       "Contínuo"),
        ("monitor-arquivos.service",  "📁 Monitor Arquivos",   "Contínuo"),
        ("usbguard.service",          "🔌 Bloqueio USB",       "Contínuo"),
        ("fail2ban.service",          "🚫 Fail2Ban",           "Contínuo"),
        ("notifica-boot.service",     "💡 Notif. Boot",        "OneShot"),
        ("notifica-shutdown.service", "🔴 Notif. Shutdown",    "OneShot"),
        ("limpeza-semanal.timer",     "🧹 Limpeza Semanal",    "Timer"),
        ("relatorio-semanal.timer",   "📊 Relatório Semanal",  "Timer"),
    ]

    for svc, name, tipo in services:
        servicos.add_row(name, get_service_status(svc), tipo)

    procs = Table(title="⚡ TOP PROCESSOS (CPU)", border_style="yellow", expand=True)
    procs.add_column("Processo", style="bold white")
    procs.add_column("CPU%", justify="right")
    procs.add_column("RAM%", justify="right")
    procs.add_column("PID", justify="right", style="dim")

    processos = sorted(
        psutil.process_iter(["name", "cpu_percent", "memory_percent", "pid"]),
        key=lambda p: p.info["cpu_percent"],
        reverse=True
    )[:8]

    for p in processos:
        try:
            cpu_p = p.info["cpu_percent"]
            ram_p = p.info["memory_percent"]
            cpu_c = "green" if cpu_p < 20 else "yellow" if cpu_p < 60 else "red"
            procs.add_row(
                Text(str(p.info["name"] or "desconhecido")[:25], no_wrap=True),
                f"[{cpu_c}]{cpu_p:.1f}%[/{cpu_c}]",
                f"{ram_p:.1f}%",
                str(p.info["pid"])
            )
        except:
            pass

    header = Panel(
        Text(f"🛡️  KALI SECURITY BUNKER  |  {now}  |  voide@PC000  |  Atualiza a cada 3s",
             justify="center", style="bold white"),
        style="bold blue"
    )

    return header, recursos, servicos, procs


def build_layout(snapshot):
    header, recursos, servicos, procs = snapshot
    layout = Layout()
    layout.split_column(
        Layout(header, size=3),
        Layout(name="meio"),
        Layout(procs, size=12),
    )
    layout["meio"].split_row(Layout(recursos), Layout(servicos))
    return layout


def collect_in_background(stop_event):
    global _snapshot
    while not stop_event.is_set():
        try:
            fresh = make_dashboard()
            with _snapshot_lock:
                _snapshot = fresh
        except Exception:
            pass
        stop_event.wait(3)

def main():
    global _snapshot
    console.clear()
    stop_event = threading.Event()
    collector = threading.Thread(target=collect_in_background, args=(stop_event,), daemon=True)
    collector.start()
    try:
        while _snapshot is None and collector.is_alive():
            time.sleep(0.05)
        with Live(console=console, refresh_per_second=10, screen=True) as live:
            while True:
                with _snapshot_lock:
                    current = _snapshot
                if current is not None:
                    live.update(build_layout(current), refresh=True)
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

if __name__ == "__main__":
    main()
