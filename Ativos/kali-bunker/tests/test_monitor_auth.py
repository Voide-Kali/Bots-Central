from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))


def load_monitor_auth():
    module_path = PROJECT_DIR / "monitor-auth.py"
    spec = importlib.util.spec_from_file_location("monitor_auth_for_tests", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Nao foi possivel carregar monitor-auth.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class MonitorAuthTests(unittest.TestCase):
    def test_collects_all_auth_failures_from_a_journal_batch(self) -> None:
        monitor_auth = load_monitor_auth()
        text = (
            "sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2\n"
            "sshd[2]: Invalid user admin from 203.0.113.11 port 22\n"
        )

        events = monitor_auth.find_auth_events(text)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].origem, "203.0.113.10")
        self.assertEqual(events[1].origem, "203.0.113.11")

    def test_geolocation_is_disabled_by_default(self) -> None:
        monitor_auth = load_monitor_auth()
        self.assertEqual(monitor_auth.GEOLOCATION_ENABLED, 0)

    def test_ignores_kde_auth_failure_after_remote_unlock(self) -> None:
        monitor_auth = load_monitor_auth()
        event = monitor_auth.AuthEvent(
            usuario="voide",
            origem="local/desconhecida",
            linha="PC000 kscreenlocker_greet[1]: pam_unix(kde:auth): authentication failure; user=voide",
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "remote-unlock-requested"
            marker.write_text("100.0", encoding="utf-8")
            with (
                patch.object(monitor_auth, "REMOTE_UNLOCK_MARKER", marker),
                patch.object(monitor_auth, "REMOTE_UNLOCK_IGNORE_SECONDS", 30),
            ):
                self.assertTrue(monitor_auth.should_ignore_auth_event(event, now=120.0))
                self.assertFalse(monitor_auth.should_ignore_auth_event(event, now=140.0))

    def test_does_not_ignore_remote_auth_failure(self) -> None:
        monitor_auth = load_monitor_auth()
        event = monitor_auth.AuthEvent(
            usuario="root",
            origem="203.0.113.10",
            linha="sshd[1]: Failed password for root from 203.0.113.10 port 22 ssh2",
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "remote-unlock-requested"
            marker.write_text("100.0", encoding="utf-8")
            with patch.object(monitor_auth, "REMOTE_UNLOCK_MARKER", marker):
                self.assertFalse(monitor_auth.should_ignore_auth_event(event, now=110.0))


if __name__ == "__main__":
    unittest.main()
