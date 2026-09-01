from __future__ import annotations

import unittest

from shared_core.ai_provider import provider_order


class ProviderOrderTests(unittest.TestCase):
    def test_prefers_requested_provider_when_available(self) -> None:
        self.assertEqual(
            provider_order(
                "openai",
                {"gemini": True, "openai": True},
                ("gemini", "openai"),
            ),
            ["openai", "gemini"],
        )

    def test_falls_back_to_defaults_when_requested_provider_is_unknown(self) -> None:
        self.assertEqual(
            provider_order(
                "auto",
                {"gemini": True, "openai": False},
                ("gemini", "openai"),
            ),
            ["gemini"],
        )

    def test_filters_unavailable_providers(self) -> None:
        self.assertEqual(
            provider_order(
                "gemini",
                {"gemini": False, "openai": True},
                ("gemini", "openai"),
            ),
            ["openai"],
        )


if __name__ == "__main__":
    unittest.main()
