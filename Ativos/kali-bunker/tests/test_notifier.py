from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import notifier


class NotifierTests(unittest.TestCase):
    @patch("notifier.time.sleep")
    @patch("notifier.requests.post")
    def test_telegram_retries_then_succeeds(self, post: Mock, _sleep: Mock) -> None:
        failure = notifier.requests.ConnectionError("offline")
        success = Mock()
        success.raise_for_status.return_value = None
        post.side_effect = [failure, failure, success]

        with (
            patch.object(notifier, "TELEGRAM_BOT_TOKEN", "token"),
            patch.object(notifier, "TELEGRAM_CHAT_ID", "chat"),
        ):
            sent = notifier._send_telegram(
                "Teste",
                "Mensagem",
                photo_path=None,
                url=None,
            )

        self.assertTrue(sent)
        self.assertEqual(post.call_count, 3)

    def test_telegram_error_redacts_token_from_output(self) -> None:
        response = notifier.requests.Response()
        response.status_code = 401
        response.url = "https://api.telegram.org/botFAKE_SECRET_TOKEN/sendMessage"
        with (
            patch.object(notifier, "TELEGRAM_BOT_TOKEN", "FAKE_SECRET_TOKEN"),
            patch.object(notifier, "TELEGRAM_CHAT_ID", "123"),
            patch.object(notifier.requests, "post", return_value=response),
            patch.object(notifier.time, "sleep"),
            patch("builtins.print") as print_mock,
        ):
            sent = notifier._send_telegram("Teste", "Mensagem", photo_path=None, url=None)

        output = " ".join(str(arg) for call in print_mock.call_args_list for arg in call.args)
        self.assertFalse(sent)
        self.assertNotIn("FAKE_SECRET_TOKEN", output)
        self.assertIn("<telegram-token>", output)


if __name__ == "__main__":
    unittest.main()
