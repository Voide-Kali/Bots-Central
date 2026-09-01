import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import pc_bridge


class PcBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.old_db = pc_bridge.DB_FILE
        self.old_artifacts = pc_bridge.ARTIFACT_DIR
        pc_bridge.DB_FILE = root / "bridge.db"
        pc_bridge.ARTIFACT_DIR = root / "artifacts"
        pc_bridge._INITIALIZED_DB = None
        pc_bridge.init_db()

    def tearDown(self):
        pc_bridge.DB_FILE = self.old_db
        pc_bridge.ARTIFACT_DIR = self.old_artifacts
        pc_bridge._INITIALIZED_DB = None
        self.temporary.cleanup()

    def test_long_poll_returns_job_without_repeated_agent_metadata_updates(self):
        created = pc_bridge.enqueue_job("status", {}, now=100)
        with patch.object(pc_bridge, "_upsert_agent", wraps=pc_bridge._upsert_agent) as upsert:
            claimed = pc_bridge.wait_for_job(
                pc_bridge.DEFAULT_AGENT_ID,
                {"hostname": "pc"},
                wait_seconds=5,
                interval_seconds=0.2,
            )
        self.assertEqual(claimed["job_id"], created["job_id"])
        self.assertEqual(upsert.call_count, 1)

    def test_long_poll_uses_read_probe_while_queue_is_idle(self):
        monotonic_values = iter([0.0, 0.0, 0.2, 1.0, 1.0])
        with (
            patch.object(pc_bridge.time, "monotonic", side_effect=lambda: next(monotonic_values)),
            patch.object(pc_bridge.time, "sleep") as sleeper,
            patch.object(pc_bridge, "claim_job", return_value=None) as claim,
            patch.object(pc_bridge, "_queued_job_exists", return_value=False) as probe,
        ):
            result = pc_bridge.wait_for_job(
                pc_bridge.DEFAULT_AGENT_ID,
                {"hostname": "pc"},
                wait_seconds=1,
                interval_seconds=0.2,
            )
        self.assertIsNone(result)
        self.assertEqual(claim.call_count, 1)
        self.assertGreaterEqual(probe.call_count, 1)
        self.assertGreaterEqual(sleeper.call_count, 1)

    def test_repeated_init_reuses_initialized_schema(self):
        initialized = pc_bridge._INITIALIZED_DB
        pc_bridge.init_db()
        self.assertEqual(pc_bridge._INITIALIZED_DB, initialized)
        self.assertTrue(pc_bridge.DB_FILE.is_file())

    def test_queue_indexes_cover_hot_paths(self):
        connection = pc_bridge._connect()
        try:
            names = {
                row[1]
                for row in connection.execute("PRAGMA index_list('pc_jobs')").fetchall()
            }
        finally:
            connection.close()
        self.assertIn("idx_pc_jobs_agent_recent", names)
        self.assertIn("idx_pc_jobs_running_lease", names)
        self.assertIn("idx_pc_jobs_queue_ready", names)
        self.assertIn("idx_pc_jobs_pending_notice", names)

    def test_job_runs_through_queue_and_notification(self):
        created = pc_bridge.enqueue_job(
            "network_scan",
            {"target": "192.168.1.0/24"},
            description="Mapear a rede",
            requested_by="telegram:test",
            now=100,
        )
        self.assertEqual(created["status"], "queued")

        claimed = pc_bridge.claim_job(
            pc_bridge.DEFAULT_AGENT_ID,
            {"hostname": "kali", "version": "1"},
            now=101,
        )
        self.assertEqual(claimed["job_id"], created["job_id"])
        self.assertEqual(claimed["payload"]["target"], "192.168.1.0/24")

        self.assertTrue(
            pc_bridge.complete_job(
                created["job_id"],
                pc_bridge.DEFAULT_AGENT_ID,
                ok=True,
                result_text="2 hosts ativos",
                now=102,
            )
        )
        notices = pc_bridge.pending_notifications()
        self.assertEqual([item["job_id"] for item in notices], [created["job_id"]])
        self.assertTrue(pc_bridge.mark_notified(created["job_id"]))
        self.assertEqual(pc_bridge.pending_notifications(), [])

    def test_offline_job_remains_queued_until_agent_returns(self):
        created = pc_bridge.enqueue_job("status", {}, now=200)
        self.assertEqual(pc_bridge.get_job(created["job_id"])["status"], "queued")
        claimed = pc_bridge.claim_job(pc_bridge.DEFAULT_AGENT_ID, {"hostname": "pc"}, now=900)
        self.assertEqual(claimed["job_id"], created["job_id"])

    def test_cancel_queued_and_request_cancel_running(self):
        queued = pc_bridge.enqueue_job("status", {})
        canceled = pc_bridge.cancel_job(queued["job_id"])
        self.assertEqual(canceled["status"], "canceled")

        running = pc_bridge.enqueue_job("shell", {"command": "uname -a"})
        pc_bridge.claim_job(pc_bridge.DEFAULT_AGENT_ID, {"hostname": "pc"})
        requested = pc_bridge.cancel_job(running["job_id"])
        self.assertEqual(requested["status"], "running")
        self.assertTrue(requested["cancel_requested"])
        renewal = pc_bridge.renew_job(running["job_id"], pc_bridge.DEFAULT_AGENT_ID)
        self.assertTrue(renewal["cancel_requested"])

    def test_artifact_must_belong_to_running_job(self):
        created = pc_bridge.enqueue_job("webcam", {})
        pc_bridge.claim_job(pc_bridge.DEFAULT_AGENT_ID, {"hostname": "pc"})
        target = pc_bridge.artifact_target(
            created["job_id"], pc_bridge.DEFAULT_AGENT_ID, ".jpg"
        )
        Path(target["path"]).write_bytes(b"jpeg")
        self.assertTrue(
            pc_bridge.complete_job(
                created["job_id"],
                pc_bridge.DEFAULT_AGENT_ID,
                ok=True,
                result_text="foto",
                artifact_name=target["name"],
            )
        )
        self.assertEqual(pc_bridge.get_job(created["job_id"])["artifact_name"], target["name"])

    def test_agent_online_state_uses_last_heartbeat(self):
        pc_bridge.heartbeat_agent("kali-principal", {"hostname": "pc"}, now=1000)
        self.assertTrue(pc_bridge.get_agent("kali-principal", now=1010)["online"])
        self.assertFalse(pc_bridge.get_agent("kali-principal", now=1100)["online"])


if __name__ == "__main__":
    unittest.main()
