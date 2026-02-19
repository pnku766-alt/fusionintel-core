from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Tuple

from contracts.schemas import ArtifactEnvelope
from sovereignty_compliance import GateDecision as Layer4Decision
from delivery_action import DeliveryDecision as Layer5Decision


def _unique_sorted(items: Iterable[str]) -> Tuple[str, ...]:
    return tuple(sorted({s for s in items if isinstance(s, str) and s.strip()}))


@dataclass(frozen=True)
class AuditPolicy:
    include_payload: bool = True
    redact_payload_keys: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditEvent:
    ts_utc: str
    artifact_id: str
    producer_layer: str
    jurisdiction: str
    residency_class: str
    layer4_allow: bool
    layer4_reasons: Tuple[str, ...]
    layer5_action: str
    layer5_allow: bool
    layer5_reasons: Tuple[str, ...]
    payload_snapshot: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts_utc": self.ts_utc,
            "artifact_id": self.artifact_id,
            "producer_layer": self.producer_layer,
            "jurisdiction": self.jurisdiction,
            "residency_class": self.residency_class,
            "layer4": {"allow": self.layer4_allow, "reasons": list(self.layer4_reasons)},
            "layer5": {"allow": self.layer5_allow, "action": self.layer5_action, "reasons": list(self.layer5_reasons)},
            "payload_snapshot": self.payload_snapshot,
        }


def build_audit_event(
    envelope: ArtifactEnvelope,
    layer4: Layer4Decision,
    layer5: Layer5Decision,
    policy: AuditPolicy = AuditPolicy(),
) -> AuditEvent:
    ts = datetime.now(timezone.utc).isoformat()

    jt = envelope.jurisdiction_tags
    payload_snapshot: dict[str, Any] | None = None
    if policy.include_payload:
        raw = envelope.payload if isinstance(envelope.payload, dict) else {}
        redactions = {k for k in policy.redact_payload_keys if isinstance(k, str) and k}
        payload_snapshot = {k: v for k, v in raw.items() if str(k) not in redactions}

    return AuditEvent(
        ts_utc=ts,
        artifact_id=str(envelope.artifact_id),
        producer_layer=str(envelope.producer_layer),
        jurisdiction=str(jt.jurisdiction),
        residency_class=str(jt.residency_class),
        layer4_allow=bool(layer4.allow),
        layer4_reasons=_unique_sorted(layer4.reasons),
        layer5_action=str(layer5.action.value if hasattr(layer5.action, "value") else layer5.action),
        layer5_allow=bool(layer5.allow),
        layer5_reasons=_unique_sorted(layer5.reasons),
        payload_snapshot=payload_snapshot,
    )


def write_audit_event(path: str, event: AuditEvent) -> None:
    import json
    line = json.dumps(event.to_dict(), sort_keys=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
