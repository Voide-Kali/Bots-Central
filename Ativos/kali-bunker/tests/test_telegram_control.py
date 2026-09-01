from __future__ import annotations

import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from action_policy import canonical_action_digest
import telegram_control


def pending_item(action: str, payload: dict[str, object]) -> dict[str, object]:
    return {
        "action": action,
        "payload": payload,
        "action_digest": canonical_action_digest(action, payload),
    }


class TelegramControlTests(unittest.TestCase):
    def setUp(self) -> None:
        telegram_control._VAULT_SESSIONS.clear()
        telegram_control._VAULT_INPUTS.clear()
        telegram_control._VAULT_CONFIRMATIONS.clear()
        feature_patcher = patch.object(telegram_control, "remote_action_enabled", return_value=True)
        feature_patcher.start()
        self.addCleanup(feature_patcher.stop)

    def test_redact_token_hides_bot_token(self) -> None:
        with patch.object(telegram_control, "TELEGRAM_BOT_TOKEN", "123:secret"):
            self.assertEqual(
                telegram_control.redact_token("url https://api.telegram.org/bot123:secret/getUpdates"),
                "url https://api.telegram.org/bot<token>/getUpdates",
            )

    def test_allowed_chat_ids_from_config(self) -> None:
        with patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123, 456"):
            self.assertTrue(telegram_control.is_allowed_chat("123"))
            self.assertTrue(telegram_control.is_allowed_chat(456))
            self.assertFalse(telegram_control.is_allowed_chat("999"))

    def test_allowed_user_ids_fall_back_to_default_chat_id(self) -> None:
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", ""),
            patch.object(telegram_control, "TELEGRAM_CHAT_ID", "123"),
        ):
            self.assertTrue(telegram_control.is_allowed_user("123"))
            self.assertFalse(telegram_control.is_allowed_user("999"))

    def test_message_requires_allowed_chat_and_sender(self) -> None:
        message = {"chat": {"id": "123"}, "from": {"id": "999"}, "text": "oi"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "456"),
            patch.object(telegram_control, "handle_ai") as handle_ai,
            patch.object(telegram_control, "record_event") as record_event,
        ):
            telegram_control.handle_message(message)
        handle_ai.assert_not_called()
        record_event.assert_called_once()

    def test_callback_requires_allowed_chat_and_sender(self) -> None:
        callback = {
            "id": "cb1",
            "from": {"id": "999"},
            "message": {"chat": {"id": "123"}},
            "data": "menu:status",
        }
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "456"),
            patch.object(telegram_control, "status_text") as status_text,
            patch.object(telegram_control, "answer_callback") as answer_callback,
            patch.object(telegram_control, "record_event") as record_event,
        ):
            telegram_control.handle_callback(callback)
        status_text.assert_not_called()
        answer_callback.assert_called_once()
        record_event.assert_called_once()

    def test_polling_config_does_not_require_default_chat_id(self) -> None:
        with (
            patch.object(telegram_control, "TELEGRAM_BOT_TOKEN", "token"),
            patch.object(telegram_control, "TELEGRAM_CHAT_ID", ""),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "-100123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "456"),
        ):
            self.assertIsNone(telegram_control.polling_config_error())

    def test_get_updates_reports_transport_failure(self) -> None:
        with patch.object(telegram_control, "telegram_request", return_value=None):
            self.assertIsNone(telegram_control.get_updates(None))

    def test_update_offset_is_persisted_before_handler_and_blocks_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            offset_file = Path(directory) / "offset.json"
            observed_offsets: list[int] = []

            def observe_handler(_message: dict[str, object]) -> None:
                state = json.loads(offset_file.read_text(encoding="utf-8"))
                observed_offsets.append(state[telegram_control.TELEGRAM_OFFSET_KEY])

            update = {"update_id": 77, "message": {"text": "oi"}}
            with (
                patch.object(telegram_control, "TELEGRAM_OFFSET_FILE", offset_file),
                patch.object(telegram_control, "handle_message", side_effect=observe_handler),
                patch.object(telegram_control, "record_event"),
            ):
                self.assertEqual(telegram_control.process_update_at_most_once(update), 78)
                self.assertEqual(telegram_control.process_update_at_most_once(update), 78)

            self.assertEqual(observed_offsets, [78])

    def test_corrupt_offset_fails_closed_instead_of_replaying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            offset_file = Path(directory) / "offset.json"
            offset_file.write_text("corrupt", encoding="utf-8")
            with patch.object(telegram_control, "TELEGRAM_OFFSET_FILE", offset_file):
                with self.assertRaises(RuntimeError):
                    telegram_control.load_telegram_offset()

    def test_authorized_sender_is_bound_to_created_confirmation(self) -> None:
        message = {"chat": {"id": "123"}, "from": {"id": "456"}, "text": "/cmd whoami"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "456"),
            patch.object(telegram_control, "create_pending", return_value="A" * 32) as create_pending,
            patch.object(telegram_control, "send_message"),
        ):
            telegram_control.handle_message(message)

        self.assertEqual(create_pending.call_args.kwargs["user_id"], "456")

    def test_polling_retry_delay_is_exponential_and_bounded(self) -> None:
        with patch.object(telegram_control, "TELEGRAM_POLL_INTERVAL_SECONDS", 1):
            self.assertEqual(telegram_control.polling_retry_delay(1), 1)
            self.assertEqual(telegram_control.polling_retry_delay(2), 2)
            self.assertEqual(telegram_control.polling_retry_delay(7), 60)
            self.assertEqual(telegram_control.polling_retry_delay(100), 60)

    def test_device_keyboard_ignores_known_and_banned_devices(self) -> None:
        devices = [
            {"ip": "192.168.3.10", "mac": "AA:BB:CC:DD:EE:01", "known": "yes", "banned": "no"},
            {"ip": "192.168.3.20", "mac": "AA:BB:CC:DD:EE:02", "known": "no", "banned": "yes"},
            {"ip": "192.168.3.88", "mac": "AA:BB:CC:DD:EE:99", "known": "no", "banned": "no"},
        ]

        keyboard = telegram_control.device_keyboard(devices)

        self.assertIsNotNone(keyboard)
        encoded = str(keyboard)
        self.assertIn("ban_ip:192.168.3.88", encoded)
        self.assertIn("ban_mac:AA:BB:CC:DD:EE:99", encoded)
        self.assertNotIn("192.168.3.10", encoded)
        self.assertNotIn("192.168.3.20", encoded)

    def test_handle_rede_uses_default_target_and_sends_scan(self) -> None:
        device = {
            "ip": "10.9.0.50",
            "mac": "AA:BB:CC:DD:EE:99",
            "hostname": "N/D",
            "vendor": "Unknown",
        }
        with (
            patch.object(telegram_control, "default_scan_target", return_value="10.9.0.0/24"),
            patch.object(telegram_control, "scan_network_devices", return_value=[device]),
            patch.object(telegram_control, "annotate_devices", return_value=[{**device, "known": "no", "banned": "no"}]),
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_rede("123", "/rede")

        send_message.assert_called_once()
        self.assertIn("10.9.0.0/24", send_message.call_args.args[1])
        self.assertIn("10.9.0.50", send_message.call_args.args[1])

    def test_handle_cmd_creates_pending_shell_action(self) -> None:
        with (
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_cmd("123", "/cmd whoami")

        create_pending.assert_called_once()
        self.assertEqual(create_pending.call_args.args[1], "shell")
        self.assertEqual(create_pending.call_args.args[2], {"command": "whoami"})
        self.assertIn("/confirmar ABC123", send_message.call_args.args[1])
        self.assertIn("inline_keyboard", send_message.call_args.args[2])

    def test_handle_confirm_executes_pending_shell_action(self) -> None:
        with (
            patch.object(
                telegram_control,
                "pop_pending",
                return_value=pending_item("shell", {"command": "whoami"}),
            ),
            patch.object(telegram_control, "execute_shell", return_value=(0, "voide")) as execute_shell,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_confirm("123", "/confirmar ABC123")

        execute_shell.assert_called_once_with("whoami")
        self.assertIn("voide", send_message.call_args.args[1])

    def test_execute_pending_webcam_sends_and_removes_photo(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            photo = Path(tmpdir) / "webcam.jpg"
            photo.write_bytes(b"jpg")
            with (
                patch.object(
                    telegram_control,
                    "pop_pending",
                    return_value=pending_item("webcam", {}),
                ),
                patch.object(telegram_control, "capture_webcam_photo", return_value=(str(photo), "Foto")),
                patch.object(telegram_control, "send_document", return_value=True) as send_document,
                patch.object(telegram_control, "send_message") as send_message,
            ):
                telegram_control.execute_pending_action("123", "ABC123")

            send_document.assert_called_once_with("123", str(photo), "Foto")
            self.assertFalse(photo.exists())
            self.assertIn("Foto enviada", send_message.call_args.args[1])

    def test_execute_pending_file_removes_temporary_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            folder = root / "docs"
            folder.mkdir()
            (folder / "readme.txt").write_text("ok", encoding="utf-8")
            sent_paths: list[Path] = []

            def send_document(_chat_id: str, path: str, _caption: str) -> bool:
                sent_path = Path(path)
                self.assertTrue(sent_path.exists())
                sent_paths.append(sent_path)
                return True

            with (
                patch.object(
                    telegram_control,
                    "pop_pending",
                    return_value=pending_item("send_path", {"path": str(folder)}),
                ),
                patch("remote_control.REMOTE_FILE_EXPORT_ENABLED", True),
                patch("remote_control.REMOTE_EXPORT_ALLOWED_ROOTS", str(root)),
                patch.object(telegram_control, "send_document", side_effect=send_document),
                patch.object(telegram_control, "send_message"),
            ):
                telegram_control.execute_pending_action("123", "A" * 32)

            self.assertEqual(len(sent_paths), 1)
            self.assertFalse(sent_paths[0].exists())

    def test_direct_webcam_call_is_refused_when_disabled(self) -> None:
        with patch.object(telegram_control, "remote_action_enabled", return_value=False):
            photo, message = telegram_control.capture_webcam_photo()
        self.assertIsNone(photo)
        self.assertIn("REMOTE_WEBCAM_ENABLED=1", message)

    def test_handle_ai_creates_pending_from_assistant_action(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "send_path", "path": "~/Documentos", "explanation": "Enviar Documentos"},
            ),
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message"),
        ):
            telegram_control.handle_ai("123", "/ia envie documentos")

        create_pending.assert_called_once()
        self.assertEqual(create_pending.call_args.args[1], "send_path")
        self.assertEqual(create_pending.call_args.args[2], {"path": "~/Documentos"})

    def test_handle_ai_creates_pending_install_package_action(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "install_package", "package": "nmap", "explanation": "Instalar nmap"},
            ),
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message"),
        ):
            telegram_control.handle_ai("123", "/ia instalar nmap")

        create_pending.assert_called_once()
        self.assertEqual(create_pending.call_args.args[1], "install_package")
        self.assertEqual(create_pending.call_args.args[2], {"package": "nmap"})

    def test_handle_ai_creates_pending_webcam_action(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "webcam", "explanation": "Capturar webcam"},
            ),
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message"),
        ):
            telegram_control.handle_ai("123", "/ia tira foto da webcam")

        create_pending.assert_called_once()
        self.assertEqual(create_pending.call_args.args[1], "webcam")

    def test_handle_ai_purge_messages_explains_supported_cleanup(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "purge_bot_messages", "explanation": "Limpar mensagens"},
            ),
            patch.object(telegram_control, "create_pending") as create_pending,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_ai("123", "/ia apaga suas mensagens")

        create_pending.assert_not_called()
        self.assertIn("/limparia", send_message.call_args.args[1])

    def test_handle_ai_sends_chat_response(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "chat", "response": "Olá, estou aqui."},
            ) as ai_assistant,
            patch.object(telegram_control, "create_pending") as create_pending,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_ai("123", "/ia oi")

        create_pending.assert_not_called()
        ai_assistant.assert_called_once_with("oi", "123")
        send_message.assert_called_once_with("123", "Olá, estou aqui.")

    def test_handle_ai_does_not_require_activation(self) -> None:
        with (
            patch.object(
                telegram_control,
                "ai_assistant",
                return_value={"action": "chat", "response": "status em texto"},
            ) as ai_assistant,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_ai("123", "/ia status")

        ai_assistant.assert_called_once_with("status", "123")
        send_message.assert_called_once_with("123", "status em texto")

    def test_handle_message_routes_plain_text_to_enabled_ai(self) -> None:
        message = {"chat": {"id": "123"}, "from": {"id": "123"}, "text": "oi"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "handle_ai") as handle_ai,
        ):
            telegram_control.handle_message(message)

        handle_ai.assert_called_once_with("123", "/ia oi", "123")

    def test_handle_study_routes_to_ai_with_study_prompt(self) -> None:
        with patch.object(telegram_control, "handle_ai") as handle_ai:
            telegram_control.handle_study("123", "/estudar redes", "estudar")

        handle_ai.assert_called_once()
        self.assertEqual(handle_ai.call_args.args[0], "123")
        self.assertIn("plano de estudo", handle_ai.call_args.args[1])
        self.assertIn("redes", handle_ai.call_args.args[1])

    def test_handle_study_requires_topic(self) -> None:
        with patch.object(telegram_control, "send_message") as send_message:
            telegram_control.handle_study("123", "/quiz", "quiz")

        send_message.assert_called_once_with("123", "Uso: /quiz TEMA")

    def test_handle_callback_menu_ia_shows_ready_message(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "menu:ia"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback") as answer_callback,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_callback(callback)

        answer_callback.assert_called_once()
        self.assertIn("IA pronta", send_message.call_args.args[1])

    def test_main_keyboard_includes_vault_menu(self) -> None:
        self.assertIn("vault:menu", str(telegram_control.main_keyboard()))
        self.assertIn("menu:ia", str(telegram_control.main_keyboard()))

    def test_ai_keyboard_has_useful_shortcuts(self) -> None:
        encoded = str(telegram_control.ai_keyboard())

        self.assertIn("ai:study", encoded)
        self.assertIn("ai:diagnose", encoded)
        self.assertIn("ai:ask", encoded)
        self.assertIn("ai:clear", encoded)
        self.assertNotIn("ai:fps", encoded)
        self.assertNotIn("ai:tools", encoded)

    def test_main_keyboard_has_professional_sections(self) -> None:
        encoded = str(telegram_control.main_keyboard())

        self.assertIn("menu:services", encoded)
        self.assertIn("menu:terminal", encoded)
        self.assertIn("menu:arquivo", encoded)

    def test_services_callback_creates_confirmed_action(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "svc:restart"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback"),
            patch.object(telegram_control, "request_confirmation") as request_confirmation,
        ):
            telegram_control.handle_callback(callback)

        request_confirmation.assert_called_once()
        self.assertEqual(request_confirmation.call_args.args[1], "bunker_services")
        self.assertEqual(request_confirmation.call_args.args[2], {"operation": "restart"})
        self.assertEqual(request_confirmation.call_args.args[4], "123")

    def test_network_menu_does_not_scan_until_scan_button(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "menu:rede"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback"),
            patch.object(telegram_control, "handle_rede") as handle_rede,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_callback(callback)

        handle_rede.assert_not_called()
        self.assertIn("Rede", send_message.call_args.args[1])

    def test_network_scan_button_runs_scan(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "net:scan"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback"),
            patch.object(telegram_control, "handle_rede") as handle_rede,
        ):
            telegram_control.handle_callback(callback)

        handle_rede.assert_called_once_with("123", "/rede")

    def test_ai_study_button_routes_to_ai_prompt(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "ai:study"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback"),
            patch.object(telegram_control, "handle_ai") as handle_ai,
        ):
            telegram_control.handle_callback(callback)

        handle_ai.assert_called_once()
        self.assertIn("plano", handle_ai.call_args.args[1].lower())

    def test_ai_diagnose_button_routes_to_ai_prompt(self) -> None:
        callback = {"id": "cb1", "from": {"id": "123"}, "message": {"chat": {"id": "123"}}, "data": "ai:diagnose"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "answer_callback"),
            patch.object(telegram_control, "handle_ai") as handle_ai,
        ):
            telegram_control.handle_callback(callback)

        handle_ai.assert_called_once()
        self.assertIn("diagnosticar", handle_ai.call_args.args[1].lower())

    def test_handle_message_routes_vault_command(self) -> None:
        message = {"chat": {"id": "123"}, "from": {"id": "123"}, "message_id": 77, "text": "/senhas"}
        with (
            patch.object(telegram_control, "TELEGRAM_ALLOWED_CHAT_IDS", "123"),
            patch.object(telegram_control, "TELEGRAM_ALLOWED_USER_IDS", "123"),
            patch.object(telegram_control, "handle_vault_command") as handle_vault_command,
        ):
            telegram_control.handle_message(message)

        handle_vault_command.assert_called_once_with("123", "/senhas", 77)

    def test_vault_unlock_deletes_sensitive_message_and_stores_session(self) -> None:
        with (
            patch.object(telegram_control.voice_vault, "unlock", return_value=2) as unlock,
            patch.object(telegram_control, "delete_message") as delete_message,
            patch.object(telegram_control, "send_message") as send_message,
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.handle_vault_command("123", "/senhas desbloquear mestra forte", 88)

        unlock.assert_called_once_with("mestra forte")
        delete_message.assert_called_once_with("123", 88)
        self.assertEqual(telegram_control._VAULT_SESSIONS["123"]["master_password"], "mestra forte")
        self.assertIn("Cofre desbloqueado", send_message.call_args.args[1])

    def test_vault_unlock_deletes_message_before_decryption(self) -> None:
        events: list[str] = []
        with (
            patch.object(telegram_control, "delete_message", side_effect=lambda *_args: events.append("deleted")),
            patch.object(
                telegram_control.voice_vault,
                "unlock",
                side_effect=lambda *_args: events.append("unlocked") or 1,
            ),
            patch.object(telegram_control, "send_message"),
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.handle_vault_command("123", "/senhas desbloquear mestra forte", 88)

        self.assertEqual(events, ["deleted", "unlocked"])

    def test_direct_vault_call_is_refused_when_disabled(self) -> None:
        with (
            patch.object(telegram_control, "remote_action_enabled", return_value=False),
            patch.object(telegram_control.voice_vault, "unlock") as unlock,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_vault_unlock("123", "mestra forte")
        unlock.assert_not_called()
        self.assertIn("REMOTE_VAULT_ENABLED=1", send_message.call_args.args[1])

    def test_vault_generate_unsaved_password_is_protected(self) -> None:
        with (
            patch.object(telegram_control.voice_vault, "generate_password", return_value="SenhaForte123!") as generate,
            patch.object(telegram_control, "send_message") as send_message,
        ):
            telegram_control.handle_vault_command("123", "/senhas gerar 18")

        generate.assert_called_once_with(18)
        self.assertIn("SenhaForte123!", send_message.call_args.args[1])
        self.assertTrue(send_message.call_args.kwargs["protect_content"])

    def test_vault_partial_find_creates_reveal_confirmation(self) -> None:
        telegram_control._vault_set_session("123", "mestra")
        entry = {
            "label": "GitHub",
            "username": "voide",
            "password": "SenhaForte123!",
            "url": "https://github.com",
            "notes": "",
        }
        with (
            patch.object(telegram_control.voice_vault, "find_entry", side_effect=[None, entry]),
            patch.object(
                telegram_control.voice_vault,
                "search_entries",
                return_value=[{"label": "GitHub", "username": "voide", "url": "https://github.com"}],
            ),
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message") as send_message,
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.handle_vault_command("123", "/senhas buscar git")

        create_pending.assert_called_once()
        self.assertEqual(create_pending.call_args.args[1], "vault_reveal")
        self.assertNotIn("SenhaForte123!", send_message.call_args.args[1])
        self.assertIn("/confirmar ABC123", send_message.call_args.args[1])

    def test_vault_confirm_reveal_sends_protected_secret(self) -> None:
        telegram_control._vault_set_session("123", "mestra")
        reference = "a" * 24
        telegram_control._VAULT_CONFIRMATIONS[reference] = {
            "chat_id": "123",
            "label": "GitHub",
            "expires_at": 9999999999,
        }
        entry = {
            "label": "GitHub",
            "username": "voide",
            "password": "SenhaForte123!",
            "url": "https://github.com",
            "notes": "",
        }
        with (
            patch.object(
                telegram_control,
                "pop_pending",
                return_value=pending_item("vault_reveal", {"ref": reference}),
            ),
            patch.object(telegram_control.voice_vault, "find_entry", return_value=entry),
            patch.object(telegram_control, "send_message") as send_message,
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.execute_pending_action("123", "ABC123")

        self.assertIn("SenhaForte123!", send_message.call_args.args[1])
        self.assertTrue(send_message.call_args.kwargs["protect_content"])

    def test_vault_delete_creates_confirmation_before_removing(self) -> None:
        telegram_control._vault_set_session("123", "mestra")
        with (
            patch.object(telegram_control.voice_vault, "find_entry", return_value={"label": "Email"}),
            patch.object(telegram_control.voice_vault, "delete_entry") as delete_entry,
            patch.object(telegram_control, "create_pending", return_value="ABC123") as create_pending,
            patch.object(telegram_control, "send_message") as send_message,
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.handle_vault_command("123", "/senhas apagar Email")

        delete_entry.assert_not_called()
        self.assertEqual(create_pending.call_args.args[1], "vault_delete")
        self.assertIn("/confirmar ABC123", send_message.call_args.args[1])

    def test_vault_confirm_delete_removes_entry(self) -> None:
        telegram_control._vault_set_session("123", "mestra")
        reference = "b" * 24
        telegram_control._VAULT_CONFIRMATIONS[reference] = {
            "chat_id": "123",
            "label": "Email",
            "expires_at": 9999999999,
        }
        with (
            patch.object(
                telegram_control,
                "pop_pending",
                return_value=pending_item("vault_delete", {"ref": reference}),
            ),
            patch.object(telegram_control.voice_vault, "delete_entry", return_value=True) as delete_entry,
            patch.object(telegram_control, "send_message") as send_message,
            patch.object(telegram_control, "record_event"),
        ):
            telegram_control.execute_pending_action("123", "ABC123")

        delete_entry.assert_called_once_with("mestra", "Email")
        self.assertIn("Senha apagada", send_message.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
