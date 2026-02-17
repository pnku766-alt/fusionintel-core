from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class JurisdictionTags:
    # Safe defaults so minimal construction works.
    jurisdiction: str = ""
    residency_class: str = ""
    export_control_flags: tuple[str, ...] = ()
    sanctions_flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProvenanceRef:
    # Optional provenance (defaults are harmless stubs).
    event_hash: str = "sha256:stub"
    signature_ref: str = "sigstub:stub"
    ledger_ref: str | None = None


@dataclass(frozen=True)
class ArtifactEnvelope:
    artifact_id: str = ""
    artifact_type: str = ""
    producer_layer: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    jurisdiction_tags: JurisdictionTags = field(default_factory=JurisdictionTags)
    provenance_ref: ProvenanceRef = field(default_factory=ProvenanceRef)