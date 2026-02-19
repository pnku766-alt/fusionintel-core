# FusionIntel Reference Architecture (Draft)

## Status
SYSTEM FORMED, ENFORCEMENT ACTIVE

## Layers
- L4: sovereignty / jurisdiction gate
- L5: action decision (deliver/deny/quarantine/review)
- L6: audit governance (audit_required, payload snapshotting + redaction)

## Core invariants
- Fail-closed
- Deterministic
- Policy-as-data (signed)
- Minimal immutable audit
- Local ≡ CI ≡ Prod
