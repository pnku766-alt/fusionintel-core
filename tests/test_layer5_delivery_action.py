from __future__ import annotations

import unittest

from contracts.schemas import ArtifactEnvelope, JurisdictionTags
from delivery_action import DeliveryAction, DeliveryPolicy, enforce_delivery_action, evaluate_delivery_action
from sovereignty_compliance import SovereigntyPolicy, evaluate_sovereignty


class TestLayer5DeliveryAction(unittest.TestCase):
    def test_deliver_when_no_flags_match(self) -> None:
        envelope = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(export_control_flags=("EAR99",), sanctions_flags=()))
        policy = DeliveryPolicy.from_iterables(
            blocked_export_control_flags=("ITAR",),
            blocked_sanctions_flags=("SDN",),
            quarantine_export_control_flags=("NLR",),
        )
        decision = evaluate_delivery_action(envelope, policy)
        self.assertTrue(decision.allow)
        self.assertEqual(DeliveryAction.DELIVER, decision.action)
        self.assertEqual((), decision.reasons)

    def test_quarantine_when_quarantine_flag_matches(self) -> None:
        envelope = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(export_control_flags=("NLR",), sanctions_flags=()))
        policy = DeliveryPolicy.from_iterables(quarantine_export_control_flags=("NLR",))
        decision = evaluate_delivery_action(envelope, policy)
        self.assertTrue(decision.allow)
        self.assertEqual(DeliveryAction.QUARANTINE, decision.action)
        self.assertEqual(("export_control_quarantine:NLR",), decision.reasons)

    def test_block_when_blocked_flag_matches_and_enforce_raises(self) -> None:
        envelope = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(export_control_flags=("ITAR",), sanctions_flags=("SDN",)))
        policy = DeliveryPolicy.from_iterables(blocked_export_control_flags=("ITAR",), blocked_sanctions_flags=("SDN",))
        decision = evaluate_delivery_action(envelope, policy)
        self.assertTrue(decision.deny)
        self.assertEqual(DeliveryAction.BLOCK, decision.action)
        self.assertEqual(("export_control_blocked:ITAR", "sanctions_blocked:SDN"), decision.reasons)

        with self.assertRaises(PermissionError):
            enforce_delivery_action(envelope, policy)

    def test_optional_layer4_chaining_blocks_with_prefixed_reasons(self) -> None:
        env = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(jurisdiction="CN", residency_class="restricted"))
        layer4 = evaluate_sovereignty(env, SovereigntyPolicy.from_iterables(allowed_jurisdictions=("US",)))
        self.assertTrue(layer4.deny)

        policy = DeliveryPolicy.from_iterables(require_layer4_allow=True)

        d = evaluate_delivery_action(env, layer4, policy)
        self.assertTrue(d.deny)
        self.assertEqual(DeliveryAction.BLOCK, d.action)
        self.assertEqual(("layer4:jurisdiction_not_allowed:CN",), d.reasons)

        with self.assertRaises(PermissionError) as ctx:
            enforce_delivery_action(env, layer4, policy)
        self.assertIn("Layer5 delivery denied:", str(ctx.exception))
        self.assertIn("layer4:jurisdiction_not_allowed:CN", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
