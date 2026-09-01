from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import summarizer


class ExternalSummaryPrivacyTests(unittest.TestCase):
    def test_external_summary_is_disabled_by_default(self) -> None:
        with (
            patch.object(summarizer.config, "AI_EMAIL_SUMMARY_ENABLED", False, create=True),
            patch.object(summarizer, "GROQ_API_KEY", "configured-test-key"),
            patch.object(summarizer.requests, "post") as post,
        ):
            result = summarizer.summarize_email(
                "sender@example.com",
                "subject",
                "private body",
                "safe snippet",
            )

        self.assertEqual(result, "safe snippet")
        post.assert_not_called()

    def test_provider_error_log_does_not_include_response_body(self) -> None:
        response = SimpleNamespace(
            status_code=400,
            text="sensitive provider response body",
        )
        with (
            patch.object(summarizer.config, "AI_EMAIL_SUMMARY_ENABLED", True, create=True),
            patch.object(summarizer, "GROQ_API_KEY", "configured-test-key"),
            patch.object(summarizer, "GROQ_MODEL", "test-model"),
            patch.object(summarizer.requests, "post", return_value=response),
            self.assertLogs(summarizer.logger, level="WARNING") as logs,
        ):
            result = summarizer.summarize_email(
                "sender@example.com",
                "subject",
                "private body",
                "safe snippet",
            )

        self.assertEqual(result, "safe snippet")
        self.assertNotIn("sensitive provider response body", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
