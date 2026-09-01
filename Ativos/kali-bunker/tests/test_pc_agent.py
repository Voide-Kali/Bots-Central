import unittest
from unittest.mock import patch

import pc_agent


class PcAgentTests(unittest.TestCase):
    def test_network_target_accepts_private_ipv4(self):
        self.assertEqual(pc_agent._validate_network_target("192.168.10.0/24"), "192.168.10.0/24")
        self.assertEqual(pc_agent._validate_network_target("10.0.0.7"), "10.0.0.7")

    def test_network_target_rejects_options_and_public_ranges(self):
        for target in ("--script=test", "8.8.8.8", "0.0.0.0/0"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                pc_agent._validate_network_target(target)

    def test_shell_is_argv_without_shell_operators(self):
        self.assertEqual(
            pc_agent._shell_argv("ssh voide@100.87.201.41 uname -a"),
            ["ssh", "voide@100.87.201.41", "uname", "-a"],
        )
        with self.assertRaises(ValueError):
            pc_agent._shell_argv("uname -a; id")

    def test_metadata_cache_reuses_expensive_snapshot_until_refresh(self):
        first = {"hostname": "pc", "telemetry": {"cpu_percent": 10}}
        second = {"hostname": "pc", "telemetry": {"cpu_percent": 20}}
        cache = pc_agent.MetadataCache(refresh_seconds=30)

        with (
            patch.object(pc_agent, "collect_metadata", side_effect=[first, second]) as collect,
            patch.object(pc_agent.time, "monotonic", side_effect=[0.0, 5.0, 31.0]),
        ):
            self.assertIs(cache.get(), first)
            self.assertIs(cache.get(), first)
            self.assertIs(cache.get(), second)

        self.assertEqual(collect.call_count, 2)

    def test_metadata_cache_can_be_invalidated_after_action(self):
        first = {"hostname": "pc", "services": {"a": "active"}}
        second = {"hostname": "pc", "services": {"a": "inactive"}}
        cache = pc_agent.MetadataCache(refresh_seconds=300)

        with patch.object(pc_agent, "collect_metadata", side_effect=[first, second]) as collect:
            self.assertIs(cache.get(), first)
            cache.invalidate()
            self.assertIs(cache.get(), second)

        self.assertEqual(collect.call_count, 2)

    def test_scan_formatter_organizes_hosts(self):
        raw = """Nmap scan report for router (192.168.1.1)
Host is up.
MAC Address: AA:BB:CC:DD:EE:FF (Vendor)
Nmap scan report for 192.168.1.20
Host is up.
"""
        result = pc_agent._format_scan(raw, "192.168.1.0/24")
        self.assertIn("2 host(s) ativo(s)", result)
        self.assertIn("router (192.168.1.1)", result)
        self.assertIn("Vendor", result)


if __name__ == "__main__":
    unittest.main()
