from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from state_utils import atomic_write_json, claim_monotonic_json_counter, read_json_counter


class StateUtilsTests(unittest.TestCase):
    def test_atomic_write_json_writes_private_readable_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"

            atomic_write_json(path, {"ok": True})

            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"ok": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])

    def test_monotonic_counter_claim_rejects_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offset.json"

            self.assertEqual(claim_monotonic_json_counter(path, "next", 42), (True, 42))
            self.assertEqual(claim_monotonic_json_counter(path, "next", 42), (False, 42))
            self.assertEqual(claim_monotonic_json_counter(path, "next", 41), (False, 42))
            self.assertEqual(claim_monotonic_json_counter(path, "next", 43), (True, 43))
            self.assertEqual(read_json_counter(path, "next"), 43)

    def test_monotonic_counter_fails_closed_on_corrupt_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "offset.json"
            path.write_text("not-json", encoding="utf-8")

            with self.assertRaises(ValueError):
                claim_monotonic_json_counter(path, "next", 1)


if __name__ == "__main__":
    unittest.main()
