from __future__ import annotations

import argparse
import json
import sys

from audit_log import AuditPolicy
from contracts.schemas import ArtifactEnvelope, JurisdictionTags, ProvenanceRef
from delivery_action import DeliveryPolicy
from orchestrator import OrchestratorPolicy, process_envelope
from sovereignty_compliance import SovereigntyPolicy


def _load_json(path: str | None) -> dict:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


def _build_policy(policy_raw: dict, args: argparse.Namespace) -> OrchestratorPolicy:
    layer4_raw = policy_raw.get("layer4", {})
    layer5_raw = policy_raw.get("layer5", {})
    layer6_raw = policy_raw.get("layer6", {})

    layer4 = SovereigntyPolicy.from_iterables(
        allowed_jurisdictions=layer4_raw.get("allowed_jurisdictions", []),
        allowed_residency_classes=layer4_raw.get("allowed_residency_classes", []),
        blocked_export_control_flags=layer4_raw.get("blocked_export_control_flags", []),
        blocked_sanctions_flags=layer4_raw.get("blocked_sanctions_flags", []),
    )
    layer5 = DeliveryPolicy.from_iterables(
        blocked_export_control_flags=layer5_raw.get("blocked_export_control_flags", []),
        blocked_sanctions_flags=layer5_raw.get("blocked_sanctions_flags", []),
        quarantine_export_control_flags=layer5_raw.get("quarantine_export_control_flags", []),
        quarantine_sanctions_flags=layer5_raw.get("quarantine_sanctions_flags", []),
        require_layer4_allow=layer5_raw.get("require_layer4_allow", False),
    )
    layer6 = AuditPolicy(
        include_payload=bool(layer6_raw.get("include_payload", False)),
        redact_payload_keys=tuple(layer6_raw.get("redact_payload_keys", [])),
    )

    audit_log_path = args.audit_log if args.audit_log is not None else policy_raw.get("audit_log_path")

    return OrchestratorPolicy(
        layer4=layer4,
        layer5=layer5,
        layer6=layer6,
        audit_log_path=audit_log_path,
        enforce_layer4=args.enforce_layer4,
        enforce_layer5=args.enforce_layer5,
    )


def _build_envelope(envelope_raw: dict) -> ArtifactEnvelope:
    tags_raw = envelope_raw.get("jurisdiction_tags", {})
    return ArtifactEnvelope(
        artifact_id=envelope_raw.get("artifact_id", ""),
        artifact_type=envelope_raw.get("artifact_type", ""),
        producer_layer=envelope_raw.get("producer_layer", ""),
        payload=envelope_raw.get("payload", {}),
        metadata=envelope_raw.get("metadata", {}),
        jurisdiction_tags=JurisdictionTags(
            jurisdiction=tags_raw.get("jurisdiction", ""),
            residency_class=tags_raw.get("residency_class", ""),
            export_control_flags=tuple(tags_raw.get("export_control_flags", [])),
            sanctions_flags=tuple(tags_raw.get("sanctions_flags", [])),
        ),
        provenance_ref=ProvenanceRef(),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--envelope")
    parser.add_argument("--audit-log")
    parser.add_argument("--enforce-layer4", action="store_true")
    parser.add_argument("--enforce-layer5", action="store_true")
    args = parser.parse_args(argv)

    policy_raw = _load_json(args.policy)
    envelope_raw = _load_json(args.envelope)

    policy = _build_policy(policy_raw, args)
    envelope = _build_envelope(envelope_raw)

    enforcement_error = False
    try:
        result = process_envelope(
            envelope=envelope,
            policy=policy,
            audit_log_path=args.audit_log,
            enforce_layer4=args.enforce_layer4,
            enforce_layer5=args.enforce_layer5,
        )
    except PermissionError:
        enforcement_error = True
        result = process_envelope(
            envelope=envelope,
            policy=policy,
            audit_log_path=args.audit_log,
            enforce_layer4=False,
            enforce_layer5=False,
        )

    output = {
        "layer4": {"allow": result.layer4.allow, "reasons": list(result.layer4.reasons)},
        "layer5": {"allow": result.layer5.allow, "action": result.layer5.action.value, "reasons": list(result.layer5.reasons)},
        "audit_written": result.audit_written,
        "audit_reasons": list(result.audit_reasons),
        "enforcement_error": enforcement_error,
    }
    print(json.dumps(output, sort_keys=True))

    action = result.layer5.action.value
    if enforcement_error:
        return 3
    if action == "block" or not result.layer5.allow:
        return 3
    if action == "quarantine":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())