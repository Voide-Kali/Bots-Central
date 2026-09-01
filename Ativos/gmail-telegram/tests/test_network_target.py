from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

import bot


class NetworkTargetTests(unittest.TestCase):
    def test_default_scan_target_prefers_connected_network_over_configured_target(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", "10.99.0.0/24"),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", "wlan0"),
            patch.object(bot, "active_ipv4_networks", return_value=[("docker0", "172.17.0.0/16"), ("wlan0", "192.168.15.0/24")]),
            patch.object(bot, "default_route_interface", return_value="tun0"),
        ):
            self.assertEqual(bot.default_scan_target(), "192.168.15.0/24")

    def test_default_scan_target_ignores_virtual_interfaces(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", ""),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", ""),
            patch.object(bot, "active_ipv4_networks", return_value=[("docker0", "172.17.0.0/16"), ("wlan0", "172.23.128.0/20")]),
            patch.object(bot, "default_route_interface", return_value="docker0"),
        ):
            self.assertEqual(bot.default_scan_target(), "172.23.128.0/20")

    def test_default_scan_target_falls_back_to_configured_network_when_no_route_exists(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", "10.99.0.0/24"),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", ""),
            patch.object(bot, "active_ipv4_networks", return_value=[]),
            patch.object(bot, "default_route_interface", return_value=None),
            patch.object(bot, "local_ips", return_value=[]),
        ):
            self.assertEqual(bot.default_scan_target(), "10.99.0.0/24")

    def test_default_scan_target_has_no_arbitrary_network_fallback(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", ""),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", ""),
            patch.object(bot, "active_ipv4_networks", return_value=[]),
            patch.object(bot, "default_route_interface", return_value=None),
            patch.object(bot, "local_ips", return_value=[]),
        ):
            self.assertIsNone(bot.default_scan_target())

    def test_run_network_scan_explains_missing_target(self) -> None:
        with patch.object(bot, "default_scan_target", return_value=None):
            ok, detail, hosts = bot.run_network_scan()

        self.assertFalse(ok)
        self.assertIn("NETWORK_SCAN_TARGET", detail)
        self.assertEqual(hosts, [])

    def test_default_scan_target_ignores_host_route_networks(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", "10.99.0.0/24"),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", ""),
            patch.object(bot, "active_ipv4_networks", return_value=[("tun0", "10.2.0.2/32")]),
            patch.object(bot, "default_route_interface", return_value="tun0"),
            patch.object(bot, "local_ips", return_value=["192.168.1.20"]),
        ):
            self.assertEqual(bot.default_scan_target(), "192.168.1.0/24")

    def test_validate_network_target_rejects_host_routes(self) -> None:
        self.assertFalse(bot.validate_network_target("10.2.0.2/32"))

    def test_preferred_scan_interface_ignores_vpn_default_route(self) -> None:
        with (
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", ""),
            patch.object(bot, "active_ipv4_networks", return_value=[("wlan0", "192.168.1.0/24")]),
            patch.object(bot, "default_route_interface", return_value="proton0"),
        ):
            self.assertEqual(bot.preferred_scan_interface(), "wlan0")

    def test_run_network_scan_prefers_arp_scan(self) -> None:
        commands: list[list[str]] = []

        def fake_which(name: str) -> str | None:
            return {
                "arp-scan": "/usr/sbin/arp-scan",
                "nmap": "/usr/bin/nmap",
            }.get(name)

        def fake_run(command: list[str], timeout: int = 30) -> tuple[bool, str]:
            commands.append(command)
            if command[0] == "sudo":
                return (
                    True,
                    "Interface: wlan0, datalink type: EN10MB\n"
                    "192.168.15.2\tAA:BB:CC:DD:EE:01\tVendor A\n"
                    "192.168.15.3\tAA:BB:CC:DD:EE:02\tVendor B\n",
                )
            return False, "fallback not expected"

        with (
            patch.object(bot.config, "NETWORK_SCAN_TARGET", ""),
            patch.object(bot.config, "NETWORK_SCAN_INTERFACE", "wlan0"),
            patch.object(bot.shutil, "which", side_effect=fake_which),
            patch.object(bot, "default_scan_target", return_value="192.168.15.0/24"),
            patch.object(bot, "preferred_scan_interface", return_value="wlan0"),
            patch.object(bot, "run_command_result", side_effect=fake_run),
        ):
            ok, detail, hosts = bot.run_network_scan()

        self.assertTrue(ok)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]["ip"], "192.168.15.2")
        self.assertEqual(commands[0][:3], ["sudo", "-n", "/usr/sbin/arp-scan"])
        self.assertIn("192.168.15.0/24", commands[0])
        self.assertNotIn("--localnet", commands[0])
        self.assertIn("Hosts encontrados: <b>2</b>", detail)


if __name__ == "__main__":
    unittest.main()
