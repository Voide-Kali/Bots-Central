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


class BluetoothAlarmTests(unittest.TestCase):
    def test_get_session_id_prefers_exact_user_seat0_then_fallback(self):
        bt = load_module("bluetooth_alarm", "bluetooth_alarm.py")

        completed = type(
            "Completed",
            (),
            {"stdout": "10  tty2 other seat0\n11  tty7 voide seat1\n12  tty8 voide seat0\n"},
        )()
        with patch.object(bt, "USERNAME", "voide"), patch.object(bt.subprocess, "run", return_value=completed):
            self.assertEqual(bt.get_session_id(), "12")

        completed2 = type(
            "Completed",
            (),
            {"stdout": "11  tty7 voide seat1\n"},
        )()
        with patch.object(bt, "USERNAME", "voide"), patch.object(bt.subprocess, "run", return_value=completed2):
            self.assertEqual(bt.get_session_id(), "11")


if __name__ == "__main__":
    unittest.main()

