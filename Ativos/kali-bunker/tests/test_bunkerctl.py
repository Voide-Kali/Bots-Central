from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bunkerctl


class BunkerctlTests(unittest.TestCase):
    def test_redact_env_line_hides_sensitive_values(self) -> None:
        self.assertEqual(
            bunkerctl.redact_env_line("TELEGRAM_BOT_TOKEN=secret"),
            "TELEGRAM_BOT_TOKEN=<redacted>",
        )
        self.assertEqual(
            bunkerctl.redact_env_line("TELEGRAM_CHAT_ID=123"),
            "TELEGRAM_CHAT_ID=<redacted>",
        )
        self.assertEqual(
            bunkerctl.redact_env_line("IPHONE_MAC=AA:BB"),
            "IPHONE_MAC=<redacted>",
        )
        self.assertEqual(bunkerctl.redact_env_line("ALERT_PROVIDER=telegram"), "ALERT_PROVIDER=telegram")
        self.assertEqual(bunkerctl.redact_env_line("DV_CREDENTIALS=secret"), "DV_CREDENTIALS=<redacted>")

    def test_csv_safe_cell_neutralizes_formula_prefixes(self) -> None:
        for value in ("=SUM(A1:A2)", "+cmd", "-1+2", "@evil", "  =hidden"):
            self.assertTrue(bunkerctl.csv_safe_cell(value).startswith("'"))
        self.assertEqual(bunkerctl.csv_safe_cell("hostname.local"), "hostname.local")

    def test_read_audit_entries_handles_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit_log = Path(directory) / "audit.jsonl"
            audit_log.write_text(json.dumps({"event": "test"}) + "\n", encoding="utf-8")
            with patch.object(bunkerctl, "AUDIT_LOG", audit_log):
                self.assertEqual(bunkerctl.read_audit_entries(), [{"event": "test"}])

    def test_rotate_backups_keeps_newest_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backup_dir = Path(directory)
            old = backup_dir / "kali-bunker-backup-1.tar.gz"
            middle = backup_dir / "kali-bunker-backup-2.tar.gz"
            newest = backup_dir / "kali-bunker-backup-3.tar.gz"
            for index, path in enumerate((old, middle, newest), start=1):
                path.write_text("backup", encoding="utf-8")
                os.utime(path, (index, index))

            removed = bunkerctl.rotate_backups(backup_dir, keep=2)

            self.assertEqual(removed, [old])
            self.assertFalse(old.exists())
            self.assertTrue(middle.exists())
            self.assertTrue(newest.exists())

    def test_render_report_text_contains_status(self) -> None:
        payload = {
            "health": {
                "generated_at": "2026-06-24T10:00:00-04:00",
                "host": "pc",
                "healthy": True,
                "uptime_seconds": 3600,
                "resources": {
                    "cpu_percent": 10.0,
                    "memory_percent": 20.0,
                    "disk_percent": 30.0,
                    "disk_free_gib": 40.0,
                    "load_1m": 0.1,
                    "load_5m": 0.2,
                    "load_15m": 0.3,
                    "temperature_c": None,
                },
                "services": [],
            },
            "checks": [{"name": "Alertas", "ok": True, "detail": "ok"}],
            "audit": [{"timestamp": "agora", "event": "teste"}],
        }

        report = bunkerctl.render_report_text(payload)

        self.assertIn("Kali Bunker Report", report)
        self.assertIn("Estado: SAUDAVEL", report)
        self.assertIn("teste", report)

    def test_tools_catalog_has_core_categories(self) -> None:
        categories = {tool.category for tool in bunkerctl.TOOLS}

        self.assertIn("operacao", categories)
        self.assertIn("sensor", categories)
        self.assertIn("manutencao", categories)
        self.assertTrue(any(tool.name == "bunkerctl" for tool in bunkerctl.TOOLS))

    def test_quick_commands_include_daily_shortcuts(self) -> None:
        commands = [command for command, _description in bunkerctl.QUICK_COMMANDS]

        self.assertIn("kb overview", commands)
        self.assertIn("sudo kb up", commands)
        self.assertIn("sudo kb down", commands)

    def test_command_services_controls_core_units(self) -> None:
        commands = []

        def fake_run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(bunkerctl, "CORE_SERVICE_UNITS", ("a.service", "b.service")),
            patch.object(os, "geteuid", return_value=0),
            patch.object(bunkerctl, "run_system", side_effect=fake_run),
            patch.object(bunkerctl, "record_event"),
            patch.object(bunkerctl.console, "print"),
        ):
            status = bunkerctl.command_services("start")

        self.assertEqual(status, 0)
        self.assertEqual(commands, [["systemctl", "start", "a.service"], ["systemctl", "start", "b.service"]])

    def test_ban_target_normalization(self) -> None:
        self.assertEqual(bunkerctl.normalize_ip("192.168.3.10"), "192.168.3.10")
        self.assertEqual(bunkerctl.normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        with self.assertRaises(ValueError):
            bunkerctl.normalize_ip("999.1.1.1")
        with self.assertRaises(ValueError):
            bunkerctl.normalize_mac("AA:BB")

    def test_banlist_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            banlist = Path(directory) / "banned.json"
            payload = [{"type": "ip", "value": "192.168.3.10", "reason": "teste"}]
            with patch.object(bunkerctl, "BANLIST_FILE", banlist):
                bunkerctl.save_banlist(payload)
                self.assertEqual(bunkerctl.load_banlist(), payload)

    def test_operational_owner_ids_uses_operational_home_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            with (
                patch.object(os, "geteuid", return_value=0),
                patch.object(bunkerctl, "OPERATIONAL_HOME", owner),
                patch.dict(os.environ, {"SUDO_UID": "31337", "SUDO_GID": "31337"}, clear=False),
            ):
                self.assertEqual(
                    bunkerctl.operational_owner_ids(),
                    (owner.stat().st_uid, owner.stat().st_gid),
                )

    def test_operational_owner_ids_ignores_non_root(self) -> None:
        with patch.object(os, "geteuid", return_value=1000):
            self.assertIsNone(bunkerctl.operational_owner_ids())

    def test_ban_firewall_commands_for_ip(self) -> None:
        commands = bunkerctl.ban_firewall_commands("ip", "192.168.3.10")

        self.assertIn(["iptables", "-A", "INPUT", "-s", "192.168.3.10", "-j", "DROP"], commands)
        self.assertIn(["iptables", "-A", "OUTPUT", "-d", "192.168.3.10", "-j", "DROP"], commands)

    def test_parse_nmap_scan_finds_ip_mac_and_vendor(self) -> None:
        output = """
Nmap scan report for celular (192.168.3.10)
Host is up (0.0040s latency).
MAC Address: AA:BB:CC:DD:EE:01 (Apple)
Nmap scan report for 192.168.3.88
Host is up (0.0060s latency).
MAC Address: AA:BB:CC:DD:EE:99 (Unknown)
"""

        devices = bunkerctl.parse_nmap_scan(output)

        self.assertEqual(devices[0]["ip"], "192.168.3.10")
        self.assertEqual(devices[0]["hostname"], "celular")
        self.assertEqual(devices[1]["mac"], "AA:BB:CC:DD:EE:99")
        self.assertEqual(devices[1]["vendor"], "Unknown")

    def test_default_scan_target_prefers_default_route_interface(self) -> None:
        def fake_run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
            if command == ["ip", "route", "get", "1.1.1.1"]:
                return subprocess.CompletedProcess(command, 0, "1.1.1.1 via 10.9.0.1 dev wlan1 src 10.9.0.44\n", "")
            if command == ["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "2: wlan0 inet 192.168.3.44/24 brd 192.168.3.255 scope global wlan0\n"
                    "3: wlan1 inet 10.9.0.44/24 brd 10.9.0.255 scope global wlan1\n",
                    "",
                )
            return subprocess.CompletedProcess(command, 1, "", "erro")

        with patch.object(bunkerctl, "run_system", side_effect=fake_run):
            self.assertEqual(bunkerctl.default_scan_target(), "10.9.0.0/24")

    def test_default_scan_target_falls_back_to_hostname_ip(self) -> None:
        def fake_run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
            if command == ["hostname", "-I"]:
                return subprocess.CompletedProcess(command, 0, "172.20.5.44\n", "")
            return subprocess.CompletedProcess(command, 1, "", "erro")

        with patch.object(bunkerctl, "run_system", side_effect=fake_run):
            self.assertEqual(bunkerctl.default_scan_target(), "172.20.5.0/24")

    def test_default_scan_target_uses_configured_local_network(self) -> None:
        with (
            patch.object(bunkerctl, "active_ipv4_networks", return_value=[]),
            patch.object(bunkerctl, "hostname_ipv4_networks", return_value=[]),
            patch.object(bunkerctl, "default_route_interface", return_value=None),
            patch.dict(os.environ, {"NETWORK_SCAN_TARGET": "192.168.8.42/24"}),
        ):
            self.assertEqual(bunkerctl.default_scan_target(), "192.168.8.0/24")

    def test_default_scan_target_refuses_arbitrary_fallback(self) -> None:
        with (
            patch.object(bunkerctl, "active_ipv4_networks", return_value=[]),
            patch.object(bunkerctl, "hostname_ipv4_networks", return_value=[]),
            patch.object(bunkerctl, "default_route_interface", return_value=None),
            patch.dict(os.environ, {}, clear=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "NETWORK_SCAN_TARGET"):
                bunkerctl.default_scan_target()

    def test_select_scanned_device_by_index_ip_and_mac(self) -> None:
        devices = [
            {"index": "1", "ip": "192.168.3.10", "mac": "AA:BB:CC:DD:EE:01"},
            {"index": "2", "ip": "192.168.3.88", "mac": "AA:BB:CC:DD:EE:99"},
        ]

        self.assertEqual(bunkerctl.select_scanned_device(devices, selected_index=2), devices[1])
        self.assertEqual(bunkerctl.select_scanned_device(devices, selected_ip="192.168.3.10"), devices[0])
        self.assertEqual(bunkerctl.select_scanned_device(devices, selected_mac="aa-bb-cc-dd-ee-99"), devices[1])

    def test_scan_network_falls_back_to_arp_scan_when_nmap_fails(self) -> None:
        commands = []

        def fake_which(command: str) -> str | None:
            return {("nmap"): "/usr/bin/nmap", ("arp-scan"): "/usr/sbin/arp-scan"}.get(command)

        def fake_run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[0] == "/usr/bin/nmap":
                return subprocess.CompletedProcess(command, 1, "", "nmap falhou")
            return subprocess.CompletedProcess(
                command,
                0,
                "192.168.3.10\tAA:BB:CC:DD:EE:01\tApple\n",
                "",
            )

        with (
            patch.object(bunkerctl.shutil, "which", side_effect=fake_which),
            patch.object(os, "geteuid", return_value=0),
            patch.object(bunkerctl, "run_system", side_effect=fake_run),
        ):
            devices = bunkerctl.scan_network_devices("192.168.3.0/24")

        self.assertEqual(devices[0]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(commands[0], ["/usr/bin/nmap", "-sn", "192.168.3.0/24"])
        self.assertEqual(commands[1][-1], "192.168.3.0/24")

    def test_scan_network_rejects_option_injection(self) -> None:
        with (
            patch.object(bunkerctl.shutil, "which", return_value="/usr/sbin/arp-scan"),
            patch.object(bunkerctl, "run_system") as run_system,
        ):
            with self.assertRaisesRegex(ValueError, "Alvo de scan invalido"):
                bunkerctl.scan_network_devices("--file=/etc/shadow")
        run_system.assert_not_called()

    def test_atomic_write_replaces_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim.txt"
            victim.write_text("intacto", encoding="utf-8")
            target = root / "known.txt"
            target.symlink_to(victim)
            bunkerctl.atomic_write_text(target, "novo\n")
            self.assertEqual(victim.read_text(encoding="utf-8"), "intacto")
            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "novo\n")

    def test_network_learn_merges_known_macs(self) -> None:
        devices = [
            {"ip": "192.168.3.10", "mac": "AA:BB:CC:DD:EE:01"},
            {"ip": "192.168.3.11", "mac": "AA:BB:CC:DD:EE:02"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            known_file = Path(directory) / "known.txt"
            known_file.write_text("AA:BB:CC:DD:EE:99\n", encoding="utf-8")
            with (
                patch.object(bunkerctl, "KNOWN_MACS_FILE", str(known_file)),
                patch.object(bunkerctl, "scan_network_devices", return_value=devices),
                patch.object(bunkerctl, "record_event"),
                patch.object(bunkerctl.console, "print"),
            ):
                status = bunkerctl.command_network_learn(
                    "192.168.3.0/24",
                    replace=False,
                    as_json=False,
                )

            self.assertEqual(status, 0)
            self.assertEqual(
                set(known_file.read_text(encoding="utf-8").splitlines()),
                {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:99"},
            )

    def test_ban_scan_registers_selected_device_ip_and_mac(self) -> None:
        device = {
            "ip": "192.168.3.88",
            "mac": "AA:BB:CC:DD:EE:99",
            "hostname": "N/D",
            "vendor": "Unknown",
        }
        with tempfile.TemporaryDirectory() as directory:
            banlist = Path(directory) / "banned.json"
            with (
                patch.object(bunkerctl, "BANLIST_FILE", banlist),
                patch.object(bunkerctl, "scan_network_devices", return_value=[device]),
                patch.object(bunkerctl, "load_known_macs", return_value=set()),
                patch.object(bunkerctl, "render_scan_table"),
                patch.object(bunkerctl.console, "print"),
                patch.object(bunkerctl, "alert_configured", return_value=False),
            ):
                status = bunkerctl.command_ban_scan(
                    "192.168.3.0/24",
                    apply_rules=False,
                    unknown_only=False,
                    as_json=False,
                    selected_index=1,
                    selected_ip=None,
                    selected_mac=None,
                    reason="teste",
                )

                self.assertEqual(status, 0)
                self.assertEqual(
                    {(item["type"], item["value"]) for item in bunkerctl.load_banlist()},
                    {("ip", "192.168.3.88"), ("mac", "AA:BB:CC:DD:EE:99")},
                )

    def test_notify_network_ban_sends_alert_when_configured(self) -> None:
        with (
            patch.object(bunkerctl, "alert_configured", return_value=True),
            patch.object(bunkerctl, "send_alert", return_value=True) as send_alert,
            patch.object(bunkerctl.console, "print"),
        ):
            sent = bunkerctl.notify_network_ban(
                "ban por scan",
                [("ip", "192.168.3.88"), ("mac", "AA:BB:CC:DD:EE:99")],
                "teste",
                applied=True,
                failures=0,
            )

        self.assertTrue(sent)
        send_alert.assert_called_once()


if __name__ == "__main__":
    unittest.main()
