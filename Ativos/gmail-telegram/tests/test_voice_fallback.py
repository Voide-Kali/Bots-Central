from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bot

try:
    import remote_control
except ImportError:
    remote_control = None


@unittest.skipUnless(
    remote_control is not None,
    "integração opcional com Kali-Bunker não está instalada",
)
class TestFallbackFunctionality(unittest.TestCase):
    def test_fallback_plan_shell_prefixes(self):
        self.assertIsNotNone(remote_control.fallback_plan("terminal: ls -la"))
        self.assertEqual(remote_control.fallback_plan("terminal: ls -la")["command"], "ls -la")

        self.assertIsNotNone(remote_control.fallback_plan("cmd: pwd"))
        self.assertEqual(remote_control.fallback_plan("cmd: pwd")["command"], "pwd")

        self.assertIsNotNone(remote_control.fallback_plan("comando: whoami"))
        self.assertEqual(remote_control.fallback_plan("comando: whoami")["command"], "whoami")

        self.assertIsNotNone(remote_control.fallback_plan("executar: uptime"))
        self.assertEqual(remote_control.fallback_plan("executar: uptime")["command"], "uptime")

    def test_fallback_plan_shell_no_prefix_parsing(self):
        # Test fallback when prefix is used without colon, e.g. "terminal ls -la"
        # The code uses prompt.split(None, 1)[1].strip()
        self.assertIsNotNone(remote_control.fallback_plan("terminal ls -la"))
        self.assertEqual(remote_control.fallback_plan("terminal ls -la")["command"], "ls -la")

    def test_fallback_plan_path_prefixes(self):
        self.assertIsNotNone(remote_control.fallback_plan("arquivo: /etc/passwd"))
        self.assertEqual(remote_control.fallback_plan("arquivo: /etc/passwd")["path"], "/etc/passwd")

        self.assertIsNotNone(remote_control.fallback_plan("pasta: /home/exemplo"))
        self.assertEqual(remote_control.fallback_plan("pasta: /home/exemplo")["path"], "/home/exemplo")

        self.assertIsNotNone(remote_control.fallback_plan("enviar: /tmp/test.txt"))
        self.assertEqual(remote_control.fallback_plan("enviar: /tmp/test.txt")["path"], "/tmp/test.txt")

    def test_handle_voice_message_fallback_flow(self) -> None:
        chat_id = "123"

        with (
            patch("bot.allowed", return_value=True),
            patch("bot.ai_assistant") as mock_ai_action,
            patch("bot.create_pending") as mock_create_pending,
            patch("bot.edit_or_reply", new=AsyncMock()) as mock_edit_or_reply,
            patch("bot.ai_keyboard", return_value={}),
            patch.object(bot.asyncio, "to_thread", new=AsyncMock(side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))),
        ):
            new_message = SimpleNamespace(text="terminal: ls -la", message_id=8, delete=AsyncMock(), reply_text=AsyncMock())
            new_update = SimpleNamespace(effective_chat=SimpleNamespace(id=123), message=new_message, effective_message=new_message)
            context = SimpleNamespace()

            mock_ai_action.return_value = remote_control.fallback_plan("terminal: ls -la")

            asyncio.run(bot.handle_voice_message(new_update, context))

            mock_create_pending.assert_called_once()
            args, _ = mock_create_pending.call_args
            self.assertEqual(args[1], "shell")
            self.assertEqual(args[2]["command"], "ls -la")

    def test_handle_voice_message_bot_message_purge_flow(self) -> None:
        with (
            patch("bot.allowed", return_value=True),
            patch("bot.ai_assistant") as mock_ai_action,
            patch("bot.create_pending") as mock_create_pending,
            patch("bot.edit_or_reply", new=AsyncMock()),
            patch("bot.ai_keyboard", return_value={}),
            patch.object(bot.asyncio, "to_thread", new=AsyncMock(side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))),
        ):
            new_message = SimpleNamespace(text="apague todas as mensagens do bot", message_id=8, delete=AsyncMock(), reply_text=AsyncMock())
            new_update = SimpleNamespace(effective_chat=SimpleNamespace(id=123), message=new_message, effective_message=new_message)
            context = SimpleNamespace()

            mock_ai_action.return_value = remote_control.fallback_plan("apague todas as mensagens do bot")

            asyncio.run(bot.handle_voice_message(new_update, context))

            mock_create_pending.assert_called_once()
            args, _ = mock_create_pending.call_args
            self.assertEqual(args[1], "purge_bot_messages")

if __name__ == "__main__":
    unittest.main()
