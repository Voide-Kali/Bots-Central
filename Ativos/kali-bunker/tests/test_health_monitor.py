from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import health_monitor


class HealthMonitorTests(unittest.TestCase):
    def test_save_json_is_atomic_and_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            health_monitor.save_json(path, {"healthy": True})
            self.assertEqual(json.loads(path.read_text()), {"healthy": True})
            self.assertFalse(path.with_suffix(".tmp").exists())


if __name__ == "__main__":
    unittest.main()
