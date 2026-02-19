from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Tuple, Union, overload

from contracts.schemas import ArtifactEnvelope
from sovereignty_compliance import GateDecision as Layer4Decision


def _norm_set(values: Iterable[str]) -> frozenset[str]:
    out: list[str] = []
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            out.append(s)
    return frozenset(out)


def _unique_sorted(items: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted({s for s in items if isinstance(s, str) and s.strip()}))


class DeliveryAction(str, Enum):
    DELIVER = "deliver"
    QUARANTINE = "quarantine"
    BLOCK = "block"


@dataclass(frozen=True)
class DeliveryPolicy:
    blocked_export_control_flags: frozenset[str] = frozenset()
    blocked_sanctions_flags: frozenset[str] = frozenset()
    quarantine_export_control_flags: frozenset[str] = frozenset()
    quarantine_sanctions_flags: frozenset[str] = frozenset()
    require_layer4_allow: bool = False

    @classmethod
    def from_iterables(
        cls,
        *,
        blocked_export_control_flags: Iterable[str] = (),
        blocked_sanctions_flags: Iterable[str] = (),
        quarantine_export_control_flags: Iterable[str] = (),
        quarantine_sanctions_flags: Iterable[str] = (),
        require_layer4_allow: bool = False,
    ) -> "DeliveryPolicy":
        return cls(
            blocked_export_control_flags=_norm_set(blocked_export_control_flags),
            blocked_sanctions_flags=_norm_set(blocked_sanctions_flags),
            quarantine_export_control_flags=_norm_set(quarantine_export_control_flags),
            quarantine_sanctions_flags=_norm_set(quarantine_sanctions_flags),
            require_layer4_allow=bool(require_layer4_allow),
        )


@dataclass(frozen=True)
class DeliveryDecision:
    allow: bool
    action: DeliveryAction = DeliveryAction.DELIVER
    reasons: Tuple[str, ...] = ()

    @property
    def deny(self) -> bool:
        return not self.allow


def _evaluate_flags_only(envelope: ArtifactEnvelope, policy: DeliveryPolicy) -> DeliveryDecision:
    jt = envelope.jurisdiction_tags
    export_flags = {str(s).strip() for s in jt.export_control_flags if str(s).strip()}
    sanctions_flags = {str(s).strip() for s in jt.sanctions_flags if str(s).strip()}

    block_reasons: list[str] = []
    quarantine_reasons: list[str] = []

    for flag in export_flags.intersection(policy.blocked_export_control_flags):
        block_reasons.append(f"export_control_blocked:{flag}")
    for flag in sanctions_flags.intersection(policy.blocked_sanctions_flags):
        block_reasons.append(f"sanctions_blocked:{flag}")

    for flag in export_flags.intersection(policy.quarantine_export_control_flags):
        quarantine_reasons.append(f"export_control_quarantine:{flag}")
    for flag in sanctions_flags.intersection(policy.quarantine_sanctions_flags):
        quarantine_reasons.append(f"sanctions_quarantine:{flag}")

    if block_reasons:
        return DeliveryDecision(allow=False, action=DeliveryAction.BLOCK, reasons=_unique_sorted(block_reasons))

    if quarantine_reasons:
        return DeliveryDecision(allow=True, action=DeliveryAction.QUARANTINE, reasons=_unique_sorted(quarantine_reasons))

    return DeliveryDecision(allow=True, action=DeliveryAction.DELIVER, reasons=())


@overload
def evaluate_delivery_action(envelope: ArtifactEnvelope, policy: DeliveryPolicy) -> DeliveryDecision: ...
@overload
def evaluate_delivery_action(envelope: ArtifactEnvelope, layer4_decision: Layer4Decision, policy: DeliveryPolicy) -> DeliveryDecision: ...


def evaluate_delivery_action(
    envelope: ArtifactEnvelope,
    arg2: Union[DeliveryPolicy, Layer4Decision],
    arg3: Any = None,
) -> DeliveryDecision:
    if isinstance(arg2, DeliveryPolicy) and arg3 is None:
        return _evaluate_flags_only(envelope, arg2)

    layer4_decision = arg2  # type: ignore[assignment]
    policy = arg3
    if not isinstance(policy, DeliveryPolicy):
        raise TypeError("expected DeliveryPolicy as third argument")

    if policy.require_layer4_allow and layer4_decision.deny:
        reasons = _unique_sorted([f"layer4:{r}" for r in layer4_decision.reasons])
        return DeliveryDecision(allow=False, action=DeliveryAction.BLOCK, reasons=reasons)

    return _evaluate_flags_only(envelope, policy)


@overload
def enforce_delivery_action(envelope: ArtifactEnvelope, policy: DeliveryPolicy) -> DeliveryDecision: ...
@overload
def enforce_delivery_action(envelope: ArtifactEnvelope, layer4_decision: Layer4Decision, policy: DeliveryPolicy) -> DeliveryDecision: ...


def enforce_delivery_action(
    envelope: ArtifactEnvelope,
    arg2: Union[DeliveryPolicy, Layer4Decision],
    arg3: Any = None,
) -> DeliveryDecision:
    decision = evaluate_delivery_action(envelope, arg2, arg3)
    if decision.deny:
        raise PermissionError("Layer5 delivery denied: " + ";".join(decision.reasons))
    return decision
