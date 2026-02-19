from __future__ import annotations

import json
import os
import tempfile
import unittest

from audit_log import AuditPolicy, build_audit_event, write_audit_event
from contracts.schemas import ArtifactEnvelope, JurisdictionTags
from delivery_action import DeliveryPolicy, evaluate_delivery_action
from sovereignty_compliance import SovereigntyPolicy, evaluate_sovereignty


class TestLayer6AuditLog(unittest.TestCase):
    def test_build_event_redacts_payload_keys(self) -> None:
        env = ArtifactEnvelope(
            artifact_id="a1",
            producer_layer="layerX",
            payload={"ok": True, "pii": {"email": "x@y"}, "token": "secret"},
            jurisdiction_tags=JurisdictionTags(jurisdiction="US", residency_class="restricted"),
        )
        l4 = evaluate_sovereignty(env, SovereigntyPolicy.from_iterables(allowed_jurisdictions=("US",)))
        l5 = evaluate_delivery_action(env, DeliveryPolicy.from_iterables())

        ev = build_audit_event(env, l4, l5, AuditPolicy(include_payload=True, redact_payload_keys=("pii", "token")))
        d = ev.to_dict()
        self.assertEqual(d["artifact_id"], "a1")
        self.assertEqual(d["layer4"]["allow"], True)
        self.assertIsInstance(d["payload_snapshot"], dict)
        self.assertIn("ok", d["payload_snapshot"])
        self.assertNotIn("pii", d["payload_snapshot"])
        self.assertNotIn("token", d["payload_snapshot"])

    def test_write_jsonl_appends(self) -> None:
        env = ArtifactEnvelope(artifact_id="a2", producer_layer="layerX", payload={"x": 1})
        l4 = evaluate_sovereignty(env, SovereigntyPolicy.from_iterables())
        l5 = evaluate_delivery_action(env, DeliveryPolicy.from_iterables())
        ev = build_audit_event(env, l4, l5, AuditPolicy(include_payload=False))

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.jsonl")
            write_audit_event(path, ev)
            write_audit_event(path, ev)

            with open(path, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]

            self.assertEqual(len(lines), 2)
            obj = json.loads(lines[0])
            self.assertEqual(obj["artifact_id"], "a2")
            self.assertIsNone(obj["payload_snapshot"])


if __name__ == "__main__":
    unittest.main()
