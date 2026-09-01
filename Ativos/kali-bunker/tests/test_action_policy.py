from __future__ import annotations

import unittest

from action_policy import (
    PolicyViolation,
    canonical_action_bytes,
    canonical_action_digest,
    validate_action_digest,
    validate_action_payload,
)


class ActionPolicyTests(unittest.TestCase):
    def test_digest_is_stable_across_parameter_order(self) -> None:
        first = {"service_action": "restart", "service_code": "WIFI"}
        second = {"service_code": "WIFI", "service_action": "restart"}

        self.assertEqual(
            canonical_action_digest("service", first),
            canonical_action_digest("service", second),
        )
        self.assertIn(b'"policy_version":1', canonical_action_bytes("service", first))

    def test_digest_comparison_detects_parameter_tampering(self) -> None:
        payload = {"service_action": "start", "service_code": "BT"}
        digest = canonical_action_digest("service", payload)

        self.assertTrue(validate_action_digest("service", payload, digest))
        self.assertFalse(
            validate_action_digest(
                "service",
                {"service_action": "stop", "service_code": "BT"},
                digest,
            )
        )

    def test_service_policy_normalizes_known_values_and_rejects_injection(self) -> None:
        action, payload = validate_action_payload(
            "service",
            {"service_action": "START", "service_code": "wifi"},
        )
        self.assertEqual(action, "service")
        self.assertEqual(payload, {"service_action": "start", "service_code": "WIFI"})

        with self.assertRaises(PolicyViolation):
            validate_action_payload(
                "service",
                {"service_action": "start;id", "service_code": "WIFI"},
            )
        with self.assertRaises(PolicyViolation):
            validate_action_payload(
                "service",
                {"service_action": "start", "service_code": "../../evil.service"},
            )

    def test_policy_rejects_unknown_actions_and_extra_shell_parameters(self) -> None:
        with self.assertRaises(PolicyViolation):
            validate_action_payload("run_anything", {})
        with self.assertRaises(PolicyViolation):
            validate_action_payload("shell", {"command": "whoami", "env": {"PATH": "/tmp"}})


if __name__ == "__main__":
    unittest.main()
