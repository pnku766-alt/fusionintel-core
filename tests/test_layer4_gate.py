from __future__ import annotations

import unittest

from contracts.schemas import ArtifactEnvelope, JurisdictionTags
from sovereignty_compliance import SovereigntyPolicy, enforce_sovereignty_gate, evaluate_sovereignty


class TestLayer4Gate(unittest.TestCase):
    def test_allows_when_policy_allows(self) -> None:
        env = ArtifactEnvelope(
            jurisdiction_tags=JurisdictionTags(
                jurisdiction="US",
                residency_class="restricted",
                export_control_flags=("EAR99",),
                sanctions_flags=("none",),
            )
        )
        policy = SovereigntyPolicy.from_iterables(
            allowed_jurisdictions=("US", "ZA"),
            allowed_residency_classes=("restricted", "public"),
            blocked_export_control_flags=("ITAR",),
            blocked_sanctions_flags=("SDN", "review"),
        )
        decision = evaluate_sovereignty(env, policy)
        self.assertTrue(decision.allow)
        self.assertEqual(decision.reasons, ())

        enforced = enforce_sovereignty_gate(env, policy)
        self.assertTrue(enforced.allow)

    def test_denies_with_reason_codes_and_sorted_unique(self) -> None:
        env = ArtifactEnvelope(
            jurisdiction_tags=JurisdictionTags(
                jurisdiction="CN",
                residency_class="foreign",
                export_control_flags=("ITAR", "ITAR"),
                sanctions_flags=("SDN",),
            )
        )
        policy = SovereigntyPolicy.from_iterables(
            allowed_jurisdictions=("US",),
            allowed_residency_classes=("restricted",),
            blocked_export_control_flags=("ITAR",),
            blocked_sanctions_flags=("SDN",),
        )
        decision = evaluate_sovereignty(env, policy)
        self.assertTrue(decision.deny)
        self.assertEqual(
            decision.reasons,
            (
                "export_control_blocked:ITAR",
                "jurisdiction_not_allowed:CN",
                "residency_class_not_allowed:foreign",
                "sanctions_blocked:SDN",
            ),
        )

    def test_enforce_raises_permission_error(self) -> None:
        env = ArtifactEnvelope(jurisdiction_tags=JurisdictionTags(jurisdiction="CN", residency_class="restricted"))
        policy = SovereigntyPolicy.from_iterables(allowed_jurisdictions=("US",))
        with self.assertRaises(PermissionError) as ctx:
            enforce_sovereignty_gate(env, policy)
        self.assertIn("Layer4 gate denied:", str(ctx.exception))
        self.assertIn("jurisdiction_not_allowed:CN", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
