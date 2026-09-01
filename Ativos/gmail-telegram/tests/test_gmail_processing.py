from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import bot
import db
import gmail_client


class GmailPaginationTests(unittest.TestCase):
    def test_unread_search_pages_past_processed_messages(self) -> None:
        messages_api = MagicMock()
        first_request = MagicMock()
        first_request.execute.return_value = {
            "messages": [{"id": "seen-1"}, {"id": "seen-2"}],
            "nextPageToken": "page-2",
        }
        second_request = MagicMock()
        second_request.execute.return_value = {"messages": [{"id": "new-1"}]}
        messages_api.list.side_effect = [first_request, second_request]

        service = MagicMock()
        service.users.return_value.messages.return_value = messages_api
        with patch.object(
            gmail_client,
            "get_email_details",
            return_value={"id": "new-1"},
        ):
            emails = gmail_client.get_unread_emails(
                service,
                1,
                excluded_ids={"seen-1", "seen-2"},
                scan_limit=10,
            )

        self.assertEqual(emails, [{"id": "new-1"}])
        self.assertEqual(messages_api.list.call_count, 2)
        self.assertEqual(messages_api.list.call_args_list[1].kwargs["pageToken"], "page-2")

    def test_unread_search_propagates_transport_failure(self) -> None:
        request = MagicMock()
        request.execute.side_effect = OSError("simulated timeout")
        messages_api = MagicMock()
        messages_api.list.return_value = request
        service = MagicMock()
        service.users.return_value.messages.return_value = messages_api

        with self.assertRaisesRegex(gmail_client.GmailClientError, "simulated timeout"):
            gmail_client.get_unread_emails(service)

    def test_unread_count_propagates_transport_failure(self) -> None:
        request = MagicMock()
        request.execute.side_effect = OSError("simulated timeout")
        labels_api = MagicMock()
        labels_api.get.return_value = request
        service = MagicMock()
        service.users.return_value.labels.return_value = labels_api

        with self.assertRaisesRegex(gmail_client.GmailClientError, "simulated timeout"):
            gmail_client.get_unread_count(service)


class GmailProcessingTests(unittest.TestCase):
    @staticmethod
    async def _inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    def test_suppressed_notification_remains_durably_queued(self) -> None:
        email = {"id": "mail-1"}
        account = {"service": object(), "email": "user@example.com"}
        with (
            patch.dict(bot.gmail_services, {"user@example.com": account}, clear=True),
            patch.object(bot.asyncio, "to_thread", new=self._inline_to_thread),
            patch.object(bot, "get_unread_emails", return_value=[email]),
            patch.object(bot.db, "seen_message_ids", return_value=set()),
            patch.object(bot.db, "is_seen", return_value=False),
            patch.object(bot.db, "enqueue_delivery", return_value=True) as enqueue,
            patch.object(bot, "is_important_email", return_value=True),
            patch.object(bot, "is_silenced", return_value=True),
            patch.object(bot, "send_notification", new=AsyncMock(return_value=False)),
            patch.object(bot.db, "mark_seen") as mark_seen,
        ):
            result = asyncio.run(bot.check_emails(SimpleNamespace()))

        self.assertEqual(result["new"], 0)
        self.assertEqual(result["queued"], 1)
        enqueue.assert_called_once_with("user@example.com", "mail-1")
        mark_seen.assert_not_called()

    def test_filtered_message_is_marked_processed(self) -> None:
        email = {"id": "mail-filtered"}
        account = {"service": object(), "email": "user@example.com"}
        with (
            patch.dict(bot.gmail_services, {"user@example.com": account}, clear=True),
            patch.object(bot.asyncio, "to_thread", new=self._inline_to_thread),
            patch.object(bot, "get_unread_emails", return_value=[email]),
            patch.object(bot.db, "seen_message_ids", return_value=set()),
            patch.object(bot.db, "is_seen", return_value=False),
            patch.object(bot, "is_important_email", return_value=False),
            patch.object(bot, "send_notification", new=AsyncMock()) as send_notification,
            patch.object(
                bot,
                "process_delivery_outbox",
                new=AsyncMock(return_value={"sent": 0, "errors": 0, "failed": 0}),
            ),
            patch.object(bot.db, "mark_seen") as mark_seen,
        ):
            result = asyncio.run(bot.check_emails(SimpleNamespace()))

        self.assertEqual(result["filtered"], 1)
        mark_seen.assert_called_once_with("user@example.com", "mail-filtered")
        send_notification.assert_not_awaited()

    def test_gmail_failure_is_counted_and_kept_in_account_state(self) -> None:
        account = {"service": object(), "email": "user@example.com"}
        failure = gmail_client.GmailClientError("simulated timeout")
        with (
            patch.dict(bot.gmail_services, {"user@example.com": account}, clear=True),
            patch.dict(bot.state.account_errors, {}, clear=True),
            patch.object(bot.asyncio, "to_thread", new=self._inline_to_thread),
            patch.object(bot, "get_unread_emails", side_effect=failure),
            patch.object(bot.db, "seen_message_ids", return_value=set()),
            patch.object(
                bot,
                "process_delivery_outbox",
                new=AsyncMock(return_value={"sent": 0, "errors": 0, "failed": 0}),
            ),
        ):
            result = asyncio.run(bot.check_emails(SimpleNamespace()))

            self.assertEqual(result["errors"], 1)
            self.assertIn("simulated timeout", bot.state.account_errors["user@example.com"])

    def test_unread_count_failure_is_not_reported_as_healthy(self) -> None:
        account = {"service": object(), "email": "user@example.com"}
        failure = gmail_client.GmailClientError("simulated timeout")
        with (
            patch.dict(bot.gmail_services, {"user@example.com": account}, clear=True),
            patch.dict(bot.state.account_errors, {}, clear=True),
            patch.object(bot.asyncio, "to_thread", new=self._inline_to_thread),
            patch.object(bot, "get_unread_count", side_effect=failure),
        ):
            counts = asyncio.run(bot.unread_counts())

            self.assertEqual(counts, {"user@example.com": -1})
            self.assertIn("simulated timeout", bot.state.account_errors["user@example.com"])

    def test_accounts_are_fetched_in_parallel_before_processing(self) -> None:
        fetched_services: list[object] = []
        started_services: list[object] = []
        gate = None
        first_service = object()
        second_service = object()
        accounts = {
            "first@example.com": {"service": first_service, "email": "first@example.com"},
            "second@example.com": {"service": second_service, "email": "second@example.com"},
        }

        def fetch(service, _max_results, *, excluded_ids):
            self.assertEqual(excluded_ids, set())
            fetched_services.append(service)
            return []

        async def concurrent_to_thread(function, *args, **kwargs):
            nonlocal gate
            if function is bot.get_unread_emails:
                if gate is None:
                    gate = asyncio.Event()
                started_services.append(args[0])
                if len(started_services) == 2:
                    gate.set()
                await asyncio.wait_for(gate.wait(), timeout=1)
            return function(*args, **kwargs)

        with (
            patch.dict(bot.gmail_services, accounts, clear=True),
            patch.dict(bot.state.account_errors, {}, clear=True),
            patch.object(bot.asyncio, "to_thread", new=concurrent_to_thread),
            patch.object(bot, "get_unread_emails", side_effect=fetch),
            patch.object(bot.db, "seen_message_ids", return_value=set()),
            patch.object(
                bot,
                "process_delivery_outbox",
                new=AsyncMock(return_value={"sent": 0, "errors": 0, "failed": 0}),
            ),
        ):
            result = asyncio.run(bot.check_emails(SimpleNamespace()))

        self.assertEqual(result["errors"], 0)
        self.assertCountEqual(started_services, [first_service, second_service])
        self.assertCountEqual(fetched_services, [first_service, second_service])


class GmailOutboxRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "gmail_bot.db"
        self.db_patch = patch.object(db, "DB_FILE", self.db_path)
        self.db_patch.start()
        db.init_db()
        bot.state.account_errors.clear()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def _settings() -> dict[str, int]:
        return {
            "max_attempts": 3,
            "lease_seconds": 30,
            "base_backoff_seconds": 10,
            "max_backoff_seconds": 60,
            "batch_size": 5,
        }

    def test_pending_message_is_reloaded_from_gmail_after_restart(self) -> None:
        address = "user@example.com"
        message_id = "mail-after-restart"
        account = {"service": object(), "email": address, "label": "Principal"}
        email = {
            "id": message_id,
            "sender": "sender@example.net",
            "subject": "Subject",
            "body": "Body",
            "snippet": "Snippet",
        }
        db.enqueue_delivery(address, message_id, now=0)

        with (
            patch.dict(bot.gmail_services, {address: account}, clear=True),
            patch.object(bot, "delivery_settings", return_value=self._settings()),
            patch.object(bot, "is_silenced", return_value=False),
            patch.object(bot, "get_email_details", return_value=email) as reload_email,
            patch.object(bot, "send_notification", new=AsyncMock(return_value=True)) as send,
            patch.object(bot.asyncio, "sleep", new=AsyncMock()),
        ):
            result = asyncio.run(bot.process_delivery_outbox(SimpleNamespace()))

        self.assertEqual(result, {"sent": 1, "errors": 0, "failed": 0})
        reload_email.assert_called_once_with(account["service"], message_id)
        send.assert_awaited_once_with(SimpleNamespace(), account, email)
        self.assertEqual(db.get_delivery(address, message_id)["status"], db.DELIVERY_SENT)

    def test_send_error_keeps_pending_and_persists_no_exception_content(self) -> None:
        address = "user@example.com"
        message_id = "mail-timeout"
        account = {"service": object(), "email": address, "label": "Principal"}
        email = {
            "id": message_id,
            "sender": "private@example.net",
            "subject": "SECRET-SUBJECT",
            "body": "SECRET-BODY",
            "snippet": "SECRET-SNIPPET",
        }
        db.enqueue_delivery(address, message_id, now=0)

        with (
            patch.dict(bot.gmail_services, {address: account}, clear=True),
            patch.object(bot, "delivery_settings", return_value=self._settings()),
            patch.object(bot, "is_silenced", return_value=False),
            patch.object(bot, "get_email_details", return_value=email),
            patch.object(
                bot,
                "send_notification",
                new=AsyncMock(side_effect=RuntimeError("SECRET-SUBJECT SECRET-BODY")),
            ),
        ):
            result = asyncio.run(bot.process_delivery_outbox(SimpleNamespace()))

        delivery = db.get_delivery(address, message_id)
        raw_database = self.db_path.read_bytes()
        self.assertEqual(result, {"sent": 0, "errors": 1, "failed": 0})
        self.assertEqual(delivery["status"], db.DELIVERY_PENDING)
        self.assertEqual(delivery["attempt_count"], 1)
        self.assertEqual(delivery["last_error"], "RuntimeError: falha durante entrega")
        self.assertNotIn(b"SECRET-SUBJECT", raw_database)
        self.assertNotIn(b"SECRET-BODY", raw_database)
        self.assertNotIn(b"SECRET-SNIPPET", raw_database)


if __name__ == "__main__":
    unittest.main()
