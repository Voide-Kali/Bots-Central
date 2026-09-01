from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from runtime_integrity import (
    MANIFEST_FILENAME,
    ManifestError,
    create_runtime_manifest,
    verify_runtime_integrity,
    write_runtime_manifest,
)


class RuntimeIntegrityTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path]:
        runtime = root / "runtime"
        systemd = root / "systemd"
        runtime.mkdir(mode=0o700)
        systemd.mkdir(mode=0o700)

        app = runtime / "app.py"
        app.write_text("print('ok')\n", encoding="utf-8")
        app.chmod(0o755)
        requirements = runtime / "requirements.txt"
        requirements.write_text("requests>=2\n", encoding="utf-8")
        requirements.chmod(0o644)
        unit = systemd / "example.service"
        unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
        unit.chmod(0o644)

        payload = create_runtime_manifest(
            runtime_source_root=runtime,
            runtime_install_root=runtime,
            runtime_files=["app.py", "requirements.txt"],
            systemd_source_root=systemd,
            systemd_install_root=systemd,
            systemd_files=["example.service"],
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        manifest = runtime / MANIFEST_FILENAME
        write_runtime_manifest(manifest, payload)
        return runtime, systemd, manifest

    def _verify(self, runtime: Path, systemd: Path, manifest: Path) -> dict[str, object]:
        return verify_runtime_integrity(
            manifest,
            expected_owner_uid=os.getuid(),
            expected_owner_gid=os.getgid(),
            expected_runtime_dir=runtime,
            expected_systemd_dir=systemd,
        )

    def test_manifest_verifies_canonical_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, systemd, manifest = self._fixture(Path(directory))

            result = self._verify(runtime, systemd, manifest)
            payload = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["checked_files"], 3)
        self.assertNotIn(".env", json.dumps(payload))

    def test_modified_file_is_reported_without_hash_or_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, systemd, manifest = self._fixture(Path(directory))
            (runtime / "app.py").write_text("SUPER_SECRET_VALUE\n", encoding="utf-8")
            (runtime / "app.py").chmod(0o755)

            result = self._verify(runtime, systemd, manifest)

        self.assertFalse(result["ok"])
        serialized = json.dumps(result, ensure_ascii=False)
        self.assertIn("runtime/app.py", serialized)
        self.assertNotIn("SUPER_SECRET_VALUE", serialized)
        self.assertNotIn("sha256", serialized)

    def test_missing_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime, systemd, manifest = self._fixture(Path(directory))
            (systemd / "example.service").unlink()

            result = self._verify(runtime, systemd, manifest)

        self.assertFalse(result["ok"])
        self.assertIn("arquivo ausente", json.dumps(result, ensure_ascii=False))

    def test_symlink_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime, systemd, manifest = self._fixture(root)
            app = runtime / "app.py"
            app.unlink()
            app.symlink_to("requirements.txt")

            result = self._verify(runtime, systemd, manifest)

        self.assertFalse(result["ok"])
        self.assertIn("tipo de arquivo inseguro", json.dumps(result, ensure_ascii=False))

    def test_generator_rejects_secret_and_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            systemd = root / "systemd"
            runtime.mkdir()
            systemd.mkdir()
            secret = runtime / ".env"
            secret.write_text("TOKEN=secret\n", encoding="utf-8")
            secret.chmod(0o644)

            with self.assertRaises(ManifestError):
                create_runtime_manifest(
                    runtime_source_root=runtime,
                    runtime_install_root=runtime,
                    runtime_files=[".env"],
                    systemd_source_root=systemd,
                    systemd_install_root=systemd,
                    systemd_files=[],
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )
            with self.assertRaises(ManifestError):
                create_runtime_manifest(
                    runtime_source_root=runtime,
                    runtime_install_root=runtime,
                    runtime_files=["../.env"],
                    systemd_source_root=systemd,
                    systemd_install_root=systemd,
                    systemd_files=[],
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )


if __name__ == "__main__":
    unittest.main()
