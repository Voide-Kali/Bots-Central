import importlib.util
from pathlib import Path
import unittest


def load_module(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MonitorWifiTests(unittest.TestCase):
    def test_parse_scan_line_accepts_valid_arp_scan_output(self):
        monitor_wifi = load_module("monitor_wifi", "monitor-wifi.py")
        parsed = monitor_wifi.parse_scan_line("192.168.1.15  AA:BB:CC:DD:EE:FF  Vendor")
        self.assertEqual(parsed, ("192.168.1.15", "AA:BB:CC:DD:EE:FF"))

    def test_parse_scan_line_rejects_invalid_lines(self):
        monitor_wifi = load_module("monitor_wifi", "monitor-wifi.py")
        self.assertIsNone(monitor_wifi.parse_scan_line("noise line"))
        self.assertIsNone(monitor_wifi.parse_scan_line("192.168.1.15  invalid-mac  Vendor"))
        self.assertIsNone(monitor_wifi.parse_scan_line("999.168.1.15  AA:BB:CC:DD:EE:FF  Vendor"))


if __name__ == "__main__":
    unittest.main()
