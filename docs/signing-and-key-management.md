# FusionIntel Key Management & Policy Signing (Phase 2)

## Goals
- Policies are data, not code
- Policies are signed + versioned
- Runtime refuses unsigned/untrusted policy bundles (fail-closed)
- Auditors can verify exact policy bytes used for any decision

## Key Hierarchy (Recommended)
1) Root governance key (offline)
2) Policy signing key (online, HSM/KMS-backed)
3) Tenant keys (optional, per-tenant isolation)

## Signing Flow (CI-controlled)
1. PR modifies policy bundle(s)
2. CI validates schema + invariants
3. Human approval gate
4. CI signs bundle with KMS/HSM key
5. Publish to policy registry

## Runtime Verification (Fail-closed)
- Validate schema
- Verify signature
- Confirm key_id trusted + not revoked
- Log policy hash activation record

## Recommendations
- ed25519 + sha256
- Sign exact bytes (avoid reformatting drift)