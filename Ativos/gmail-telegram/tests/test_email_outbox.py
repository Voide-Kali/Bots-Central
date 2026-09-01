from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import db


class EmailOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temporary.name) / "gmail_bot.db"
        self.db_patch = patch.object(db, "DB_FILE", self.db_path)
        self.db_patch.start()
        db.init_db()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temporary.cleanup()

    def test_outbox_stores_no_email_content_columns(self) -> None:
        db.enqueue_delivery("user@example.com", "gmail-id", now=100)

        with sqlite3.connect(self.db_path) as conn:
            columns = {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(email_delivery)")
            }
            raw_database = self.db_path.read_bytes()

        self.assertFalse(
            columns.intersection({"sender", "subject", "body", "snippet", "payload"})
        )
        self.assertNotIn(b"secret subject", raw_database)

    def test_legacy_seen_rows_are_migrated_without_becoming_pending(self) -> None:
        self.db_path.unlink()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE seen_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_email TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(account_email, message_id)
                )
                """
            )
            conn.execute(
                "INSERT INTO seen_emails (account_email, message_id) VALUES (?, ?)",
                ("legacy@example.com", "old-id"),
            )
        db.init_db()

        delivery = db.get_delivery("legacy@example.com", "old-id")

        self.assertIsNotNone(delivery)
        self.assertEqual(delivery["status"], db.DELIVERY_SENT)
        self.assertIsNone(
            db.claim_due_delivery(max_attempts=3, lease_seconds=30, now=100)
        )

    def test_only_one_concurrent_worker_can_claim_a_message(self) -> None:
        db.enqueue_delivery("user@example.com", "gmail-id", now=100)

        def claim():
            return db.claim_due_delivery(
                max_attempts=3,
                lease_seconds=30,
                now=100,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(executor.map(lambda _index: claim(), range(2)))

        self.assertEqual(sum(item is not None for item in claims), 1)

    def test_expired_lease_recovers_after_crash(self) -> None:
        db.enqueue_delivery("user@example.com", "gmail-id", now=100)
        first = db.claim_due_delivery(
            max_attempts=3,
            lease_seconds=30,
            now=100,
        )

        during_lease = db.claim_due_delivery(
            max_attempts=3,
            lease_seconds=30,
            now=129,
        )
        recovered = db.claim_due_delivery(
            max_attempts=3,
            lease_seconds=30,
            now=131,
        )

        self.assertIsNotNone(first)
        self.assertIsNone(during_lease)
        self.assertIsNotNone(recovered)
        self.assertNotEqual(first["lease_token"], recovered["lease_token"])
        self.assertEqual(recovered["attempt_count"], 2)

    def test_failure_uses_backoff_then_stops_at_attempt_limit(self) -> None:
        db.enqueue_delivery("user@example.com", "gmail-id", now=100)
        first = db.claim_due_delivery(
            max_attempts=2,
            lease_seconds=30,
            now=100,
        )
        deferred = db.defer_delivery(
            "user@example.com",
            "gmail-id",
            first["lease_token"],
            "TimedOut: tempo limite do Telegram",
            max_attempts=2,
            base_backoff_seconds=10,
            max_backoff_seconds=60,
            now=100,
        )

        self.assertEqual(deferred["status"], db.DELIVERY_PENDING)
        self.assertEqual(deferred["next_attempt_at"], 110)
        self.assertIsNone(
            db.claim_due_delivery(max_attempts=2, lease_seconds=30, now=109)
        )

        second = db.claim_due_delivery(
            max_attempts=2,
            lease_seconds=30,
            now=110,
        )
        terminal = db.defer_delivery(
            "user@example.com",
            "gmail-id",
            second["lease_token"],
            "NetworkError: falha de rede do Telegram",
            max_attempts=2,
            base_backoff_seconds=10,
            max_backoff_seconds=60,
            now=110,
        )

        self.assertEqual(terminal["status"], db.DELIVERY_FAILED)
        self.assertIsNone(
            db.claim_due_delivery(max_attempts=2, lease_seconds=30, now=999)
        )
        self.assertEqual(db.retry_failed_deliveries(now=1000), 1)
        reopened = db.get_delivery("user@example.com", "gmail-id")
        self.assertEqual(reopened["status"], db.DELIVERY_PENDING)
        self.assertEqual(reopened["attempt_count"], 0)

    def test_success_requires_the_current_lease(self) -> None:
        db.enqueue_delivery("user@example.com", "gmail-id", now=100)
        claim = db.claim_due_delivery(
            max_attempts=3,
            lease_seconds=30,
            now=100,
        )

        self.assertFalse(
            db.mark_delivery_sent(
                "user@example.com",
                "gmail-id",
                "wrong-token",
                now=101,
            )
        )
        self.assertTrue(
            db.mark_delivery_sent(
                "user@example.com",
                "gmail-id",
                claim["lease_token"],
                now=101,
            )
        )
        self.assertEqual(
            db.get_delivery("user@example.com", "gmail-id")["status"],
            db.DELIVERY_SENT,
        )


if __name__ == "__main__":
    unittest.main()
