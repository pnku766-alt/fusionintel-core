cd C:\Users\Admin\fusionintel-core
mkdir scripts -Force | Out-Null
notepad .\scripts\bootstrap_enforce.ps1
# paste the script content below, save, then:
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_enforce.ps1

**Right (file):**
- paste that into: `.github/workflows/<something>.yml`

**Wrong (PowerShell):**

**Right (file):**
- paste into: `pyproject.toml`

## Canonical Paths
- Workflows: `.github/workflows/*.yml`
- Pre-commit: `.pre-commit-config.yaml`
- Scripts: `scripts/*.ps1`, `scripts/*.py`
- Docs: `docs/*.md`
- Package: `fusionintel_core/**/*.py`
'@

$ciDoc = @'
# FusionIntel CI Guide

## What runs in CI
1) `pre-commit` hooks (placement validation + hygiene)
2) optional: unit tests / smoke tests (your repo may add more)

## Workflows
- `.github/workflows/precommit.yml` runs pre-commit on push/PR.

## Local usage
Install hooks once:
```powershell
python -m pip install -U pip
python -m pip install -e ".[dev,api]"
pre-commit install

---

## What this “enforces” (practically)
- If you accidentally paste **GitHub Actions YAML** into a `.ps1` or `.py`, **commit is blocked**
- If you accidentally commit `PS C:\...` transcript into non-doc files, **commit is blocked**
- CI will run the same rules on every push/PR

---

## Want it even stricter?
If you say “make it stricter”, I’ll extend `validate_placements.py` to:
- Fail if *any* `.yml` exists outside `.github/workflows` (except `docs/`)
- Fail if TOML appears outside `pyproject.toml`
- Fail if workflow keys (`on:`, `jobs:`) appear anywhere outside `.github/workflows/*.yml` and `docs/*.md`
- Enforce a canonical docs TOC + required headings

Also: you already have `scripts/audit_smoke.ps1` + `.github/workflows/smoke.yml`; we can add a CI job that **boots uvicorn and runs** your audit smoke test too (separately from pre-commit).
::contentReference[oaicite:0]{index=0}

{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://fusionintel.ai/schemas/fusionintel.policy-bundle.schema.json",
  "title": "FusionIntel Policy Bundle",
  "type": "object",
  "additionalProperties": false,
  "required": ["policy_version", "scope", "signing", "layers", "meta"],
  "properties": {
    "policy_version": {
      "type": "string",
      "description": "Semver or date-based policy version (e.g., 2026-01, 1.2.0).",
      "minLength": 1
    },
    "scope": {
      "type": "string",
      "description": "Where this policy applies.",
      "enum": ["global", "tenant", "environment", "project"]
    },
    "meta": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "owner", "created_utc"],
      "properties": {
        "name": { "type": "string", "minLength": 1 },
        "owner": { "type": "string", "minLength": 1 },
        "created_utc": { "type": "string", "format": "date-time" },
        "notes": { "type": "string" }
      }
    },
    "signing": {
      "type": "object",
      "additionalProperties": false,
      "required": ["key_id", "algorithm", "signature_required"],
      "properties": {
        "key_id": { "type": "string", "minLength": 1 },
        "algorithm": {
          "type": "string",
          "enum": ["ed25519", "ecdsa-p256", "rsa-pss-sha256"]
        },
        "signature_required": {
          "type": "boolean",
          "const": true,
          "description": "Invariant: runtime must refuse unsigned policies."
        }
      }
    },
    "tenancy": {
      "type": "object",
      "additionalProperties": false,
      "description": "Present when scope != global.",
      "properties": {
        "tenant_id": { "type": "string", "minLength": 1 },
        "policy_namespace": {
          "type": "string",
          "description": "Logical namespace boundary for policy isolation.",
          "minLength": 1
        }
      }
    },
    "layers": {
      "type": "object",
      "additionalProperties": false,
      "required": ["layer4", "layer5", "layer6"],
      "properties": {
        "layer4": { "$ref": "#/$defs/layer4" },
        "layer5": { "$ref": "#/$defs/layer5" },
        "layer6": { "$ref": "#/$defs/layer6" }
      }
    }
  },
  "$defs": {
    "nonEmptyStringArray": {
      "type": "array",
      "minItems": 1,
      "items": { "type": "string", "minLength": 1 }
    },
    "layer4": {
      "title": "Layer 4: Sovereignty / Jurisdiction Gate",
      "type": "object",
      "additionalProperties": false,
      "required": ["allowed_jurisdictions", "allowed_residency_classes"],
      "properties": {
        "allowed_jurisdictions": {
          "$ref": "#/$defs/nonEmptyStringArray",
          "description": "Allowed jurisdiction tags (e.g., US, ZA, EU)."
        },
        "allowed_residency_classes": {
          "$ref": "#/$defs/nonEmptyStringArray",
          "description": "Allowed residency classes (e.g., domestic, foreign, unknown)."
        },
        "deny_if_sanctioned": {
          "type": "boolean",
          "default": true,
          "description": "If true, any sanctions flag => deny."
        },
        "deny_if_export_controlled": {
          "type": "boolean",
          "default": true,
          "description": "If true, any export control flag => deny."
        }
      }
    },
    "layer5": {
      "title": "Layer 5: Action Decision",
      "type": "object",
      "additionalProperties": false,
      "required": ["require_layer4_allow", "default_action"],
      "properties": {
        "require_layer4_allow": {
          "type": "boolean",
          "description": "If true, layer5 cannot allow unless layer4 allowed."
        },
        "default_action": {
          "type": "string",
          "enum": ["deny", "deliver", "quarantine", "review"],
          "description": "Invariant-friendly default."
        },
        "rules": {
          "type": "array",
          "description": "Optional rules evaluated in order; first match wins.",
          "items": { "$ref": "#/$defs/layer5_rule" }
        }
      }
    },
    "layer5_rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["when", "then"],
      "properties": {
        "id": { "type": "string", "minLength": 1 },
        "when": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "artifact_type": { "type": "string", "minLength": 1 },
            "producer_layer": { "type": "string", "minLength": 1 },
            "jurisdiction": { "type": "string", "minLength": 1 },
            "residency_class": { "type": "string", "minLength": 1 },
            "has_sanctions_flags": { "type": "boolean" },
            "has_export_control_flags": { "type": "boolean" }
          }
        },
        "then": {
          "type": "object",
          "additionalProperties": false,
          "required": ["action", "allow"],
          "properties": {
            "action": { "type": "string", "enum": ["deny", "deliver", "quarantine", "review"] },
            "allow": { "type": "boolean" },
            "reason": { "type": "string" }
          }
        }
      }
    },
    "layer6": {
      "title": "Layer 6: Audit Controls",
      "type": "object",
      "additionalProperties": false,
      "required": ["audit_required", "include_payload", "redact_payload_keys"],
      "properties": {
        "audit_required": {
          "type": "boolean",
          "const": true,
          "description": "Invariant: audit cannot be disabled by policy."
        },
        "include_payload": {
          "type": "boolean",
          "description": "If true, payload_snapshot may include payload minus redactions."
        },
        "redact_payload_keys": {
          "type": "array",
          "description": "Keys removed from payload_snapshot when include_payload=true.",
          "items": { "type": "string", "minLength": 1 },
          "default": []
        },
        "audit_sinks": {
          "type": "array",
          "description": "Optional multi-sink routing (file, http, queue).",
          "items": { "$ref": "#/$defs/audit_sink" },
          "default": []
        }
      }
    },
    "audit_sink": {
      "type": "object",
      "additionalProperties": false,
      "required": ["type"],
      "properties": {
        "type": { "type": "string", "enum": ["file_jsonl", "http", "queue"] },
        "path": { "type": "string" },
        "url": { "type": "string", "format": "uri" },
        "queue_name": { "type": "string" }
      }
    }
  }
}

{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://fusionintel.ai/schemas/fusionintel.request.schema.json",
  "title": "FusionIntel Process Request",
  "type": "object",
  "additionalProperties": false,
  "required": ["policy", "envelope", "options"],
  "properties": {
    "policy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["layer4", "layer5", "layer6"],
      "properties": {
        "layer4": { "type": "object" },
        "layer5": { "type": "object" },
        "layer6": { "type": "object" }
      }
    },
    "envelope": {
      "type": "object",
      "additionalProperties": false,
      "required": ["artifact_id", "artifact_type", "producer_layer", "payload", "metadata", "jurisdiction_tags"],
      "properties": {
        "artifact_id": { "type": "string", "minLength": 1 },
        "artifact_type": { "type": "string", "minLength": 1 },
        "producer_layer": { "type": "string", "minLength": 1 },
        "payload": { "type": ["object", "array", "string", "number", "boolean", "null"] },
        "metadata": { "type": "object" },
        "jurisdiction_tags": {
          "type": "object",
          "additionalProperties": false,
          "required": ["jurisdiction", "residency_class", "export_control_flags", "sanctions_flags"],
          "properties": {
            "jurisdiction": { "type": "string", "minLength": 1 },
            "residency_class": { "type": "string", "minLength": 1 },
            "export_control_flags": { "type": "array", "items": { "type": "string" } },
            "sanctions_flags": { "type": "array", "items": { "type": "string" } }
          }
        }
      }
    },
    "options": {
      "type": "object",
      "additionalProperties": true,
      "properties": {
        "audit_log_path": { "type": "string" }
      }
    }
  }
}

# FusionIntel Key Management & Policy Signing (Phase 2)

## Goals
- Policies are **data**, not code.
- Policies are **signed** and **versioned**.
- Runtime **refuses** unsigned or untrusted policy bundles (fail-closed).
- Auditors can verify **exact policy bytes** used for any decision.

---

## Key Hierarchy (Recommended)
### 1) Root Governance Key (OFFLINE)
- Purpose: certifies intermediate keys.
- Storage: offline HSM / cold storage.
- Use frequency: rare (rotation / re-issuance only).

### 2) Policy Signing Key (ONLINE / HSM-backed)
- Purpose: signs policy bundles after CI approval.
- Storage: cloud KMS or HSM.
- Rotation: regular (e.g., quarterly).

### 3) Tenant Signing Keys (OPTIONAL, for multi-tenant)
- Purpose: tenant-scoped policy overlays (still constrained by global invariants).
- Storage: per-tenant KMS key, separate IAM boundary.

---

## Artifact Types to Sign
### A) Policy Bundle (MUST SIGN)
- Signed JSON/YAML bytes.
- Signature covers:
  - policy body
  - policy_version
  - scope
  - meta.created_utc
  - tenancy fields (if any)

### B) Runtime Policy Activation Record (MUST HASH/LOG)
- Logs:
  - policy_version
  - sha256(policy_bytes)
  - key_id
  - signature algorithm
  - activation ts_utc
  - environment (dev/stage/prod)
- Stored in append-only audit store.

---

## Signing Flow (CI-controlled)
1. Author opens PR modifying `policies/` (or equivalent)
2. CI validates:
   - JSON Schema compliance
   - Invariant checks (audit_required=true, signature_required=true, etc.)
   - policy unit tests (sample requests)
3. Human approval by policy maintainers
4. CI pipeline signs bundle using KMS/HSM key
5. Signed bundle is published to Policy Registry

---

## Verification Flow (Runtime)
1. Fetch policy bundle by explicit version
2. Validate schema
3. Verify signature using trusted public key set
4. Confirm key_id is trusted + not revoked
5. Activate policy
6. Log activation hash in audit store
7. Proceed to evaluate requests

**Fail-closed:** any failure in steps 2–5 => deny

---

## Key Rotation
- Maintain an allowlist of active signing keys.
- Publish revocation list.
- Runtime should trust:
  - current key
  - previous key(s) for rollback window
- After rotation window, revoke old keys.

---

## Minimum Cryptography Recommendations
- Preferred: **ed25519**
- Hash: **sha256**
- Sign exact bytes (no reformatting between signing and verification).
- Canonicalization:
  - For JSON: canonical JSON serializer before signing (or sign the exact stored artifact bytes).
  - For YAML: strongly prefer signing JSON representation to avoid formatting ambiguity.

---

## Operational Guardrails
- Signing key usage requires:
  - CI identity + approval gate
  - environment constraints
  - auditable event logs
- Never allow developers to sign from laptops.
- Policy registry write access is restricted to CI service principal.

---
# FusionIntel Multi-Tenant Isolation Invariants (Phase 2)

## Definition
A “tenant” is a security boundary. Cross-tenant access must be impossible by default.

---

## Hard Invariants (Non-negotiable)
### 1) No Cross-Tenant Policy Evaluation
- A request must be evaluated only under:
  - global policy + the request’s tenant overlay (if allowed)
- A tenant overlay cannot weaken global invariants.

### 2) Tenant-scoped Audit Segregation
- Audit records are tagged with `tenant_id`.
- Storage is logically or physically separated per tenant:
  - separate files, separate buckets, separate DB partitions, or separate streams.
- No tenant can read another tenant’s audit trail.

### 3) Tenant Key Isolation
- Each tenant has its own encryption keys for:
  - audit at rest (if encrypted)
  - policy overlays (if supported)
- IAM policies prevent cross-tenant key usage.

### 4) No Shared Secret Material
- No shared signing keys across tenants unless using a single global signer with strict tenancy claims.

### 5) Explicit Tenant Identity in Envelope
- Every request includes `tenant_id` (or it is derived from auth token).
- “Tenantless” requests must be rejected unless explicitly allowed (global scope services only).

### 6) Resource Quotas Per Tenant
- Prevent noisy-neighbor risks:
  - rate limits
  - payload size limits
  - audit throughput limits
  - concurrency caps

### 7) Deterministic Enforcement Per Tenant
- Same request + same policy version + same tenant => same decision.

---

## Tenant Overlay Rules (If Supported)
- Tenants can add *stricter* constraints only.
- Tenants cannot:
  - disable audit_required
  - disable signature_required
  - change fail-closed behavior
  - allow jurisdictions globally denied
- Overlay merge policy:
  - intersection for allowlists
  - union for blocklists
  - max(strictness) for booleans

---

## Threat Model Checklist
- Prevent tenant A from:
  - influencing tenant B policy selection
  - reading tenant B audit/payload snapshots
  - exhausting shared resources
  - injecting malformed policy overlays

---
# FusionIntel Reference Architecture
**Version:** 0.1 (Phase 2 Draft)  
**Status:** SYSTEM FORMED, ENFORCEMENT ACTIVE  

---

## Abstract
FusionIntel is a policy enforcement control plane for intelligence artifacts. It provides deterministic, replayable, fail-closed decisions over artifact delivery actions using layered sovereignty controls (L4), action routing (L5), and audit governance (L6). FusionIntel externalizes policy as signed data while retaining enforcement invariants within the engine.

---

## 1. Problem Statement
Modern intelligence and compliance systems fail in predictable ways:
- policy is buried in code
- enforcement differs across environments
- audit is inconsistent or excessive
- sovereignty, sanctions, and export controls are bolted on late

FusionIntel addresses these failure modes by making **policy explicit**, **enforcement deterministic**, and **audit minimal but sufficient**.

---

## 2. Design Goals
- Fail-closed enforcement
- Deterministic decisioning and replay
- Signed, versioned policy-as-data
- Minimal immutable audit
- Environment parity (local=CI=prod)
- Tenant isolation (optional mode)

---

## 3. Architecture Overview
### 3.1 Components
- **Policy Bundle** (signed data)
- **Policy Engine** (L4/L5/L6)
- **Interfaces** (API/CLI/batch)
- **Audit Sink** (append-only)

### 3.2 Control Flow
1) Receive request + envelope  
2) Load active signed policy version  
3) Evaluate Layer 4 (sovereignty gate)  
4) Evaluate Layer 5 (action decision)  
5) Evaluate Layer 6 (audit rules; snapshot policy)  
6) Return decision + write audit record  

---

## 4. Enforcement Model (Layers)
### Layer 4 — Sovereignty Gate
- jurisdiction + residency allowlists
- sanctions/export flags denial rules

### Layer 5 — Action Decision
- deliver / deny / quarantine / review
- rules evaluated deterministically in order

### Layer 6 — Audit Governance
- audit_required is immutable
- payload snapshots are policy-controlled
- redaction keys are enforced

---

## 5. Invariants
- Governance precedes execution
- Determinism over convenience
- Policy is explicit, never implied
- Audit is immutable and minimal
- Separation of powers
- Local ≡ CI ≡ Prod

---

## 6. Compliance Alignment
FusionIntel maps to global regimes via enforcement primitives:
- data sovereignty (GDPR/POPIA)
- export control flags (ITAR/EAR/Wassenaar)
- sanctions flags (OFAC/EU/UN)
- audit immutability for public sector records

FusionIntel does not encode laws; it encodes controllable, auditable enforcement behaviors required by laws.

---

## 7. Policy-as-Data
### 7.1 Policy Registry
- stores signed policy bundles by version
- supports revocation and rollout control

### 7.2 Signing and Verification
- CI signs policies with HSM/KMS-backed keys
- runtime verifies before activation
- activation hash is auditable

---

## 8. Multi-Tenant Mode (Optional)
- tenant_id is a security boundary
- policy overlays may only tighten constraints
- audit and keys are tenant-scoped
- quotas prevent noisy-neighbor risk

---

## 9. Operational Considerations
- strict schema validation
- invariant enforcement in code
- pre-commit + CI checks prevent unsafe placement and changes
- reproducible releases, pinned dependencies

---

## 10. Roadmap (Phase 2+)
- canonical policy registry implementation
- signature verification in runtime (mandatory)
- policy simulation tooling (replay)
- formal proof tests for invariants
- hardened multi-tenant deployment patterns

---
