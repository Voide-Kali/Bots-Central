import unittest

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
