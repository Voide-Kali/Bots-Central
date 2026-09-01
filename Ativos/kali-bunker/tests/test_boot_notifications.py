from __future__ import annotations

import unittest
from unittest.mock import patch

import notifica_boot
import notifica_shutdown


class BootNotificationTests(unittest.TestCase):
    def test_boot_without_alert_config_does_not_fail_systemd_unit(self) -> None:
        with patch.object(notifica_boot, "alert_configured", return_value=False):
            self.assertEqual(notifica_boot.main(), 0)

    def test_boot_send_failure_does_not_fail_systemd_unit(self) -> None:
        with (
            patch.object(notifica_boot, "alert_configured", return_value=True),
            patch.object(notifica_boot, "send_alert", return_value=False),
        ):
            self.assertEqual(notifica_boot.main(), 0)

    def test_shutdown_without_alert_config_does_not_fail_systemd_unit(self) -> None:
        with patch.object(notifica_shutdown, "alert_configured", return_value=False):
            self.assertEqual(notifica_shutdown.main(), 0)

    def test_shutdown_send_failure_does_not_fail_systemd_unit(self) -> None:
        with (
            patch.object(notifica_shutdown, "alert_configured", return_value=True),
            patch.object(notifica_shutdown, "send_alert", return_value=False),
        ):
            self.assertEqual(notifica_shutdown.main(), 0)


if __name__ == "__main__":
    unittest.main()
