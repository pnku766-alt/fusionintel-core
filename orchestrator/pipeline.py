from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from audit_log import AuditPolicy, build_audit_event, write_audit_event
from contracts.schemas import ArtifactEnvelope
from delivery_action import DeliveryDecision, DeliveryPolicy, enforce_delivery_action, evaluate_delivery_action
from sovereignty_compliance import GateDecision, SovereigntyPolicy, enforce_sovereignty_gate, evaluate_sovereignty


@dataclass(frozen=True)
class OrchestratorPolicy:
    layer4: SovereigntyPolicy
    layer5: DeliveryPolicy
    layer6: AuditPolicy = AuditPolicy()
    audit_log_path: Optional[str] = None
    enforce_layer4: bool = False
    enforce_layer5: bool = False


@dataclass(frozen=True)
class OrchestratorResult:
    layer4: GateDecision
    layer5: DeliveryDecision
    audit_written: bool
    audit_reasons: Tuple[str, ...] = ()


def process_envelope(
    envelope: ArtifactEnvelope,
    policy: OrchestratorPolicy,
    audit_log_path: Optional[str] = None,
    enforce_layer4: Optional[bool] = None,
    enforce_layer5: Optional[bool] = None,
) -> OrchestratorResult:
    eff_audit = audit_log_path if audit_log_path is not None else policy.audit_log_path
    eff_enforce_l4 = policy.enforce_layer4 if enforce_layer4 is None else bool(enforce_layer4)
    eff_enforce_l5 = policy.enforce_layer5 if enforce_layer5 is None else bool(enforce_layer5)

    # Layer 4
    if eff_enforce_l4:
        layer4 = enforce_sovereignty_gate(envelope, policy.layer4)
    else:
        layer4 = evaluate_sovereignty(envelope, policy.layer4)

    # Layer 5 (supports optional chaining)
    if policy.layer5.require_layer4_allow:
        layer5 = (
            enforce_delivery_action(envelope, layer4, policy.layer5)
            if eff_enforce_l5
            else evaluate_delivery_action(envelope, layer4, policy.layer5)
        )
    else:
        layer5 = (
            enforce_delivery_action(envelope, policy.layer5)
            if eff_enforce_l5
            else evaluate_delivery_action(envelope, policy.layer5)
        )

    # Layer 6 audit
    audit_written = False
    audit_reasons: list[str] = []
    if eff_audit:
        ev = build_audit_event(envelope, layer4, layer5, policy.layer6)
        write_audit_event(eff_audit, ev)
        audit_written = True
        audit_reasons.append("audit_written")

    return OrchestratorResult(
        layer4=layer4,
        layer5=layer5,
        audit_written=audit_written,
        audit_reasons=tuple(audit_reasons),
    )