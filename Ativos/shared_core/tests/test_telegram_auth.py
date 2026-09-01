from __future__ import annotations

import unittest
from types import SimpleNamespace

from shared_core.telegram_auth import (
    is_authorized_update,
    parse_allowed_chat_ids,
    parse_numeric_ids,
)


class ParseNumericIdsTests(unittest.TestCase):
    def test_parses_csv_ids(self) -> None:
        self.assertEqual(parse_numeric_ids("1, 2, -3"), {1, 2, -3})

    def test_rejects_invalid_values(self) -> None:
        with self.assertRaises(ValueError):
            parse_numeric_ids("1,abc")

    def test_rejects_negative_values_when_forbidden(self) -> None:
        with self.assertRaises(ValueError):
            parse_numeric_ids("-100", allow_negative=False)

    def test_allowed_chat_ids_returns_none_for_empty_input(self) -> None:
        self.assertIsNone(parse_allowed_chat_ids(""))


class AuthorizationTests(unittest.TestCase):
    def test_authorizes_only_expected_chat_and_user(self) -> None:
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=-1001),
            effective_user=SimpleNamespace(id=42),
        )
        self.assertTrue(
            is_authorized_update(
                update,
                expected_chat_id=-1001,
                allowed_user_ids={42, 99},
            )
        )

    def test_rejects_wrong_chat_or_user(self) -> None:
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(id=-1001),
            effective_user=SimpleNamespace(id=77),
        )
        self.assertFalse(
            is_authorized_update(
                update,
                expected_chat_id=-2002,
                allowed_user_ids={42, 99},
            )
        )
        self.assertFalse(
            is_authorized_update(
                update,
                expected_chat_id=-1001,
                allowed_user_ids={42, 99},
            )
        )


if __name__ == "__main__":
    unittest.main()
