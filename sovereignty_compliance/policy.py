from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from contracts.schemas import ArtifactEnvelope


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


@dataclass(frozen=True)
class SovereigntyPolicy:
    """
    Layer 4 policy:
      - allowed_jurisdictions: if non-empty, tags.jurisdiction must be in this set
      - allowed_residency_classes: if non-empty, tags.residency_class must be in this set
      - blocked_export_control_flags: any overlap => deny
      - blocked_sanctions_flags: any overlap => deny
    """

    allowed_jurisdictions: frozenset[str] = frozenset()
    allowed_residency_classes: frozenset[str] = frozenset()
    blocked_export_control_flags: frozenset[str] = frozenset()
    blocked_sanctions_flags: frozenset[str] = frozenset()

    @classmethod
    def from_iterables(
        cls,
        *,
        allowed_jurisdictions: Iterable[str] = (),
        allowed_residency_classes: Iterable[str] = (),
        blocked_export_control_flags: Iterable[str] = (),
        blocked_sanctions_flags: Iterable[str] = (),
    ) -> "SovereigntyPolicy":
        return cls(
            allowed_jurisdictions=_norm_set(allowed_jurisdictions),
            allowed_residency_classes=_norm_set(allowed_residency_classes),
            blocked_export_control_flags=_norm_set(blocked_export_control_flags),
            blocked_sanctions_flags=_norm_set(blocked_sanctions_flags),
        )


@dataclass(frozen=True)
class GateDecision:
    allow: bool
    reasons: Tuple[str, ...] = ()

    @property
    def deny(self) -> bool:
        return not self.allow


def evaluate_sovereignty(envelope: ArtifactEnvelope, policy: SovereigntyPolicy) -> GateDecision:
    jt = envelope.jurisdiction_tags
    reasons: list[str] = []

    jurisdiction = str(jt.jurisdiction).strip()
    residency_class = str(jt.residency_class).strip()

    if policy.allowed_jurisdictions and jurisdiction not in policy.allowed_jurisdictions:
        reasons.append(f"jurisdiction_not_allowed:{jurisdiction}")

    if policy.allowed_residency_classes and residency_class not in policy.allowed_residency_classes:
        reasons.append(f"residency_class_not_allowed:{residency_class}")

    export_flags = {str(s).strip() for s in jt.export_control_flags if str(s).strip()}
    sanctions_flags = {str(s).strip() for s in jt.sanctions_flags if str(s).strip()}

    for flag in export_flags.intersection(policy.blocked_export_control_flags):
        reasons.append(f"export_control_blocked:{flag}")

    for flag in sanctions_flags.intersection(policy.blocked_sanctions_flags):
        reasons.append(f"sanctions_blocked:{flag}")

    clean = _unique_sorted(reasons)
    return GateDecision(allow=(len(clean) == 0), reasons=clean)


def enforce_sovereignty_gate(envelope: ArtifactEnvelope, policy: SovereigntyPolicy) -> GateDecision:
    decision = evaluate_sovereignty(envelope, policy)
    if decision.deny:
        raise PermissionError("Layer4 gate denied: " + ";".join(decision.reasons))
    return decision