import tempfile
import unittest
from pathlib import Path

from install_support import inspect_config, render_systemd_unit


PROJECT_DIR = Path(__file__).resolve().parents[1]


class InstallConfigTests(unittest.TestCase):
    def test_telegram_config_reports_only_safe_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "Documentos"
            protected.mkdir()
            config = root / ".env"
            config.write_text(
                "ALERT_PROVIDER=telegram\n"
                "TELEGRAM_BOT_TOKEN=token-de-teste\n"
                "TELEGRAM_CHAT_ID=123\n"
                "IPHONE_MAC=AA:BB:CC:DD:EE:FF\n"
                "PROTECTED_DIR=${HOME}/Documentos\n",
                encoding="utf-8",
            )

            status = inspect_config(config, root)

        self.assertEqual(status.flags(), "1 1 1 1")
        self.assertNotIn("token-de-teste", status.flags())

    def test_pushover_does_not_enable_telegram_polling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / ".env"
            config.write_text(
                "ALERT_PROVIDER=pushover\nPUSHOVER_TOKEN=x\nPUSHOVER_USER=y\n",
                encoding="utf-8",
            )

            status = inspect_config(config, root)

        self.assertTrue(status.alert_ready)
        self.assertFalse(status.telegram_polling_ready)


class InstallUnitRenderTests(unittest.TestCase):
    def test_render_uses_protected_runtime_and_target_identity(self) -> None:
        source = """[Service]
User=voide
Group=voide
WorkingDirectory=/home/voide/Kali-Bunker-main
EnvironmentFile=-/home/voide/Kali-Bunker-main/.env
ExecStart=/usr/bin/python3 /home/voide/Kali-Bunker-main/app.py
ReadWritePaths=/home/voide/.local/state/kali-bunker
"""

        rendered = render_systemd_unit(
            source,
            target_user="alice",
            target_group="staff",
            target_home=Path("/home/alice"),
            runtime_dir=Path("/opt/kali-bunker"),
            runtime_python=Path("/opt/kali-bunker/.venv/bin/python"),
            system_config=Path("/etc/kali-bunker/kali-bunker.env"),
        )

        self.assertIn("User=alice", rendered)
        self.assertIn("Group=staff", rendered)
        self.assertIn("/opt/kali-bunker/.venv/bin/python", rendered)
        self.assertIn('Environment="KALI_BUNKER_RUNTIME_DIR=/opt/kali-bunker"', rendered)
        self.assertIn("EnvironmentFile=-/etc/kali-bunker/kali-bunker.env", rendered)
        self.assertNotIn("/home/voide", rendered)
        self.assertNotIn("/usr/bin/python3", rendered)

    def test_all_units_render_without_editable_source_paths(self) -> None:
        for unit in (PROJECT_DIR / "systemd").iterdir():
            if unit.suffix not in {".service", ".timer"}:
                continue
            rendered = render_systemd_unit(
                unit.read_text(encoding="utf-8"),
                target_user="alice",
                target_group="staff",
                target_home=Path("/home/alice"),
                runtime_dir=Path("/opt/kali-bunker"),
                runtime_python=Path("/opt/kali-bunker/.venv/bin/python"),
                system_config=Path("/etc/kali-bunker/kali-bunker.env"),
            )
            self.assertNotIn("/home/voide/Kali-Bunker-main", rendered, unit.name)
            self.assertNotIn("/usr/bin/python3", rendered, unit.name)

    def test_shutdown_notification_runs_on_service_stop(self) -> None:
        unit = (PROJECT_DIR / "systemd/notifica-shutdown.service").read_text(
            encoding="utf-8"
        )

        self.assertIn("ExecStart=/usr/bin/true", unit)
        self.assertIn("ExecStop=/usr/bin/python3", unit)
        self.assertIn("RemainAfterExit=yes", unit)
        self.assertIn("WantedBy=multi-user.target", unit)


if __name__ == "__main__":
    unittest.main()
