import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


def load_module(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MonitorAuthTests(unittest.TestCase):
    def test_build_message_contains_user_host_and_ip(self):
        with patch("socket.gethostname", return_value="kali-box"), \
             patch("time.strftime", return_value="17/05/2026 20:00:00"):
            monitor_auth = load_module("monitor_auth", "monitor-auth.py")
            with patch.object(monitor_auth, "get_local_ip", return_value="192.168.1.10"):
                msg = monitor_auth.build_message("voide")

        self.assertIn("Usuario: voide", msg)
        self.assertIn("Host: kali-box", msg)
        self.assertIn("IP local: 192.168.1.10", msg)
        self.assertIn("Horario: 17/05/2026 20:00:00", msg)

    def test_tirar_foto_returns_none_when_capture_missing(self):
        monitor_auth = load_module("monitor_auth", "monitor-auth.py")
        with patch.object(monitor_auth.subprocess, "run") as run, \
             patch.object(monitor_auth.os.path, "exists", return_value=False):
            self.assertIsNone(monitor_auth.tirar_foto())
            self.assertTrue(run.called)


if __name__ == "__main__":
    unittest.main()
