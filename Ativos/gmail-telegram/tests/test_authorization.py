import unittest
from unittest.mock import patch

import bot


class DummyIdentity:
    def __init__(self, identity_id: int):
        self.id = identity_id


class DummyUpdate:
    def __init__(self, chat_id: int | None, user_id: int | None):
        self.effective_chat = DummyIdentity(chat_id) if chat_id is not None else None
        self.effective_user = DummyIdentity(user_id) if user_id is not None else None


class TelegramAuthorizationTests(unittest.TestCase):
    def test_private_chat_fallback_allows_same_user(self):
        with (
            patch.object(bot.config, "TELEGRAM_CHAT_ID", "12345"),
            patch.object(bot.config, "TELEGRAM_ALLOWED_USER_IDS", ""),
        ):
            self.assertTrue(bot.allowed(DummyUpdate(12345, 12345)))
            self.assertFalse(bot.allowed(DummyUpdate(12345, 99999)))

    def test_group_requires_explicit_allowed_user(self):
        with (
            patch.object(bot.config, "TELEGRAM_CHAT_ID", "-100123"),
            patch.object(bot.config, "TELEGRAM_ALLOWED_USER_IDS", "555,777"),
        ):
            self.assertTrue(bot.allowed(DummyUpdate(-100123, 555)))
            self.assertFalse(bot.allowed(DummyUpdate(-100123, 999)))
            self.assertFalse(bot.allowed(DummyUpdate(-200000, 555)))

    def test_invalid_allowed_user_configuration_fails_closed(self):
        with (
            patch.object(bot.config, "TELEGRAM_CHAT_ID", "12345"),
            patch.object(bot.config, "TELEGRAM_ALLOWED_USER_IDS", "123,abc"),
        ):
            with self.assertRaises(RuntimeError):
                bot.get_allowed_user_ids()


if __name__ == "__main__":
    unittest.main()
