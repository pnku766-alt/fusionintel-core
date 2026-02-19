from __future__ import annotations

import json
import os
import tempfile
import unittest

from contracts.schemas import ArtifactEnvelope, JurisdictionTags
from delivery_action import DeliveryAction, DeliveryPolicy
from orchestrator import OrchestratorPolicy, process_envelope
from sovereignty_compliance import SovereigntyPolicy


class TestLayer7Orchestrator(unittest.TestCase):
    def test_pipeline_writes_audit_and_returns_decisions(self) -> None:
        env = ArtifactEnvelope(
            artifact_id="x1",
            producer_layer="layerX",
            payload={"ok": True, "pii": {"email": "x@y"}},
            jurisdiction_tags=JurisdictionTags(
                jurisdiction="US",
                residency_class="restricted",
                export_control_flags=("EAR99",),
                sanctions_flags=(),
            ),
        )

        l4 = SovereigntyPolicy.from_iterables(allowed_jurisdictions=("US",))
        l5 = DeliveryPolicy.from_iterables(quarantine_export_control_flags=("NLR",))

        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "audit.jsonl")
            policy = OrchestratorPolicy(layer4=l4, layer5=l5, audit_log_path=path)
            result = process_envelope(env, policy)

            self.assertTrue(result.layer4.allow)
            self.assertTrue(result.layer5.allow)
            self.assertEqual(DeliveryAction.DELIVER, result.layer5.action)
            self.assertTrue(result.audit_written)

            with open(path, "r", encoding="utf-8") as f:
                line = f.readline().strip()
            obj = json.loads(line)
            self.assertEqual(obj["artifact_id"], "x1")

    def test_pipeline_blocks_when_layer5_requires_layer4_allow(self) -> None:
        env = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(jurisdiction="CN", residency_class="restricted"))

        l4 = SovereigntyPolicy.from_iterables(allowed_jurisdictions=("US",))
        l5 = DeliveryPolicy.from_iterables(require_layer4_allow=True)

        result = process_envelope(env, OrchestratorPolicy(layer4=l4, layer5=l5))
        self.assertTrue(result.layer4.deny)
        self.assertTrue(result.layer5.deny)
        self.assertEqual(DeliveryAction.BLOCK, result.layer5.action)
        self.assertEqual(("layer4:jurisdiction_not_allowed:CN",), result.layer5.reasons)


if __name__ == "__main__":
    unittest.main()
