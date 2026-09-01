from __future__ import annotations

import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import patch

import bunker_audit
import bunker_health


class HealthTests(unittest.TestCase):
    @patch("bunker_health.run_command")
    def test_service_state_returns_stdout(self, run_command) -> None:
        run_command.return_value.stdout = "active\n"
        self.assertEqual(bunker_health.service_state("example.service"), "active")

    @patch("bunker_health.run_command", return_value=None)
    def test_service_state_handles_unavailable_systemctl(self, _run_command) -> None:
        self.assertEqual(bunker_health.service_state("example.service"), "unknown")

    @patch("bunker_health.run_command")
    def test_service_state_reports_systemd_bus_unavailable(self, run_command) -> None:
        run_command.return_value = subprocess.CompletedProcess(
            ["systemctl", "is-active", "example.service"],
            1,
            "",
            "Failed to connect to system scope bus via local transport: Operation not permitted",
        )

        self.assertEqual(bunker_health.service_state("example.service"), "unavailable")

    @patch("bunker_health.run_command")
    def test_telegram_service_state_prefers_user_unit(self, run_command) -> None:
        run_command.return_value = subprocess.CompletedProcess(
            ["systemctl", "--user", "is-active", "kali-bunker-telegram.service"],
            0,
            "active\n",
            "",
        )

        self.assertEqual(bunker_health.service_state("kali-bunker-telegram.service"), "active")

    @patch("bunker_health.run_command")
    def test_systemd_accessible_detects_permission_error(self, run_command) -> None:
        run_command.return_value = subprocess.CompletedProcess(
            ["systemctl", "is-system-running"],
            1,
            "",
            "Failed to connect to bus: Operation not permitted",
        )

        self.assertFalse(bunker_health.systemd_accessible())

    @patch("bunker_health.verify_runtime_integrity", return_value={"ok": True})
    @patch("bunker_health.psutil.cpu_percent", return_value=1.0)
    @patch("bunker_health.psutil.virtual_memory")
    @patch("bunker_health.psutil.disk_usage")
    @patch("bunker_health.os.getloadavg", return_value=(0.1, 0.2, 0.3))
    @patch("bunker_health.time.time", return_value=2000)
    @patch("bunker_health.psutil.boot_time", return_value=1000)
    @patch("bunker_health.temperature", return_value=None)
    @patch("bunker_health.local_ips", return_value=[])
    @patch("bunker_health.service_enabled", return_value="unavailable")
    @patch("bunker_health.service_state", return_value="unavailable")
    @patch("bunker_health.systemd_accessible", return_value=False)
    def test_collect_health_consolidates_systemd_unavailable(
        self,
        _systemd_accessible,
        _service_state,
        _service_enabled,
        _local_ips,
        _temperature,
        _boot_time,
        _time,
        _load,
        disk_usage,
        virtual_memory,
        _cpu,
        _integrity,
    ) -> None:
        virtual_memory.return_value.percent = 2.0
        disk_usage.return_value.percent = 3.0
        disk_usage.return_value.free = 4 * 1024**3

        report = bunker_health.collect_health()

        self.assertFalse(report["systemd_accessible"])
        self.assertEqual(report["critical_failed"], ["systemd-unavailable"])

    @patch(
        "bunker_health.verify_runtime_integrity",
        return_value={"ok": True, "checked_files": 2, "problems": []},
    )
    @patch("bunker_health.systemd_accessible", return_value=True)
    @patch("bunker_health.service_state", return_value="inactive")
    def test_doctor_allows_inactive_noncritical_services(
        self, _service_state, _systemd_accessible, _integrity
    ) -> None:
        original_services = bunker_health.SERVICES
        bunker_health.SERVICES = (
            bunker_health.ServiceSpec("optional.service", "Opcional", "OPT", critical=False),
        )
        try:
            checks = bunker_health.doctor_checks()
        finally:
            bunker_health.SERVICES = original_services

        service_check = next(item for item in checks if item["name"] == "Serviço optional.service")
        self.assertTrue(service_check["ok"])

    @patch(
        "bunker_health.verify_runtime_integrity",
        return_value={
            "ok": False,
            "checked_files": 1,
            "problems": [{"path": "runtime/app.py", "reason": "conteudo alterado"}],
        },
    )
    @patch("bunker_health.systemd_accessible", return_value=False)
    def test_doctor_reports_runtime_integrity_failure(
        self, _systemd_accessible, _integrity
    ) -> None:
        checks = bunker_health.doctor_checks()

        check = next(item for item in checks if item["name"] == "Integridade do runtime")
        self.assertFalse(check["ok"])
        self.assertIn("runtime/app.py", check["detail"])

    @patch(
        "bunker_health.verify_runtime_integrity",
        return_value={"ok": True, "checked_files": 2, "problems": []},
    )
    @patch("bunker_health.systemd_accessible", return_value=False)
    def test_doctor_requires_private_regular_env_file(
        self, _systemd_accessible, _integrity
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.env"
            target.write_text("TOKEN=secret\n", encoding="utf-8")
            target.chmod(0o644)
            config = root / ".env"
            config.symlink_to(target)
            with patch.object(bunker_health, "ENV_PATHS", (config,)):
                checks = bunker_health.doctor_checks()

        regular = next(item for item in checks if item["name"] == "Arquivo .env regular")
        permissions = next(item for item in checks if item["name"] == "Permissões do .env")
        self.assertFalse(regular["ok"])
        self.assertFalse(permissions["ok"])
        self.assertNotIn("TOKEN=secret", str(checks))

    def test_audit_writes_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory)
            with (
                patch.object(bunker_audit, "STATE_DIR", state_dir),
                patch.object(bunker_audit, "AUDIT_LOG", state_dir / "audit.jsonl"),
            ):
                bunker_audit.record_event("test", value=42)
                content = (state_dir / "audit.jsonl").read_text(encoding="utf-8")
                self.assertIn('"event": "test"', content)
                self.assertIn('"value": 42', content)


if __name__ == "__main__":
    unittest.main()
