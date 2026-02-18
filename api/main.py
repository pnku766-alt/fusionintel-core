from __future__ import annotations

import os
import uuid
from typing import Any, Optional

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from audit_log import AuditPolicy
from contracts.schemas import ArtifactEnvelope, JurisdictionTags, ProvenanceRef
from delivery_action import DeliveryPolicy
from orchestrator import OrchestratorPolicy, process_envelope
from sovereignty_compliance import SovereigntyPolicy


class ProcessOptions(BaseModel):
    audit_log_path: Optional[str] = None
    enforce_layer4: bool = False
    enforce_layer5: bool = False


class ProcessRequest(BaseModel):
    policy: dict[str, Any] = Field(default_factory=dict)
    envelope: dict[str, Any] = Field(default_factory=dict)
    options: ProcessOptions = Field(default_factory=ProcessOptions)


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name, "")
    if v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


def _build_policy(policy_raw: dict[str, Any], options: ProcessOptions) -> OrchestratorPolicy:
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

    audit_log_path = options.audit_log_path if options.audit_log_path is not None else policy_raw.get("audit_log_path")

    # allow env overrides too
    env_audit = os.getenv("FUSIONINTEL_AUDIT_LOG_PATH")
    if env_audit:
        audit_log_path = env_audit

    enforce_layer4 = bool(options.enforce_layer4) or _bool_env("FUSIONINTEL_ENFORCE_L4", False)
    enforce_layer5 = bool(options.enforce_layer5) or _bool_env("FUSIONINTEL_ENFORCE_L5", False)

    return OrchestratorPolicy(
        layer4=layer4,
        layer5=layer5,
        layer6=layer6,
        audit_log_path=audit_log_path,
        enforce_layer4=enforce_layer4,
        enforce_layer5=enforce_layer5,
    )


def _build_envelope(envelope_raw: dict[str, Any]) -> ArtifactEnvelope:
    tags_raw = envelope_raw.get("jurisdiction_tags", {}) or {}
    return ArtifactEnvelope(
        artifact_id=envelope_raw.get("artifact_id", ""),
        artifact_type=envelope_raw.get("artifact_type", ""),
        producer_layer=envelope_raw.get("producer_layer", ""),
        payload=envelope_raw.get("payload", {}) if isinstance(envelope_raw.get("payload", {}), dict) else {},
        metadata=envelope_raw.get("metadata", {}) if isinstance(envelope_raw.get("metadata", {}), dict) else {},
        jurisdiction_tags=JurisdictionTags(
            jurisdiction=tags_raw.get("jurisdiction", ""),
            residency_class=tags_raw.get("residency_class", ""),
            export_control_flags=tuple(tags_raw.get("export_control_flags", [])),
            sanctions_flags=tuple(tags_raw.get("sanctions_flags", [])),
        ),
        provenance_ref=ProvenanceRef(),
    )


app = FastAPI(title="FusionIntel Core API", version="0.2.2")


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["x-request-id"] = rid
    return response


def _require_api_key(x_api_key: Optional[str]) -> None:
    required = os.getenv("FUSIONINTEL_API_KEY", "")
    if not required:
        # no key set => auth disabled (dev-friendly)
        return
    if not x_api_key or x_api_key != required:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/process")
def process(request: Request, req: ProcessRequest, x_api_key: Optional[str] = Header(default=None)) -> dict[str, Any]:
    _require_api_key(x_api_key)

    policy = _build_policy(req.policy, req.options)
    envelope = _build_envelope(req.envelope)

    enforcement_error = False
    try:
        result = process_envelope(
            envelope=envelope,
            policy=policy,
            audit_log_path=policy.audit_log_path,
            enforce_layer4=policy.enforce_layer4,
            enforce_layer5=policy.enforce_layer5,
        )
    except PermissionError:
        enforcement_error = True
        result = process_envelope(
            envelope=envelope,
            policy=policy,
            audit_log_path=policy.audit_log_path,
            enforce_layer4=False,
            enforce_layer5=False,
        )

    return {
        "request_id": getattr(request.state, "request_id", None),
        "layer4": {"allow": result.layer4.allow, "reasons": list(result.layer4.reasons)},
        "layer5": {"allow": result.layer5.allow, "action": result.layer5.action.value, "reasons": list(result.layer5.reasons)},
        "audit_written": result.audit_written,
        "audit_reasons": list(result.audit_reasons),
        "enforcement_error": enforcement_error,
    }
