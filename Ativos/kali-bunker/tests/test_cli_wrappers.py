import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


class CliWrapperTests(unittest.TestCase):
    def test_kb_resolves_project_when_called_through_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "kb"
            link.symlink_to(PROJECT_DIR / "kb")
            result = subprocess.run(
                [link, "quick"],
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kb overview", result.stdout)

    def test_menu_resolves_project_when_called_through_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "bunker-menu"
            link.symlink_to(PROJECT_DIR / "bunker-menu")
            result = subprocess.run(
                [link],
                cwd=directory,
                input="9\n0\n",
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("kb overview", result.stdout)


if __name__ == "__main__":
    unittest.main()
