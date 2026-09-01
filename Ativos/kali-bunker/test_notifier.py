import unittest
from unittest.mock import patch


class NotifierTests(unittest.TestCase):
    def test_telegram_send_message(self):
        with patch("notifier.ALERT_PROVIDER", "telegram"), \
             patch("notifier.TELEGRAM_BOT_TOKEN", "bot-token"), \
             patch("notifier.TELEGRAM_CHAT_ID", "123"), \
             patch("notifier._SESSION.post") as post:
            post.return_value.raise_for_status.return_value = None

            from notifier import send_alert

            ok = send_alert("Titulo", "Mensagem")

        self.assertTrue(ok)
        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertIn("/sendMessage", args[0])
        self.assertEqual(kwargs["data"]["chat_id"], "123")
        self.assertIn("Titulo", kwargs["data"]["text"])

    def test_invalid_provider_is_rejected(self):
        with patch("notifier.ALERT_PROVIDER", "invalid"):
            from notifier import alert_configured, alert_config_error

            self.assertFalse(alert_configured())
            self.assertIn("invalido", alert_config_error())


if __name__ == "__main__":
    unittest.main()
