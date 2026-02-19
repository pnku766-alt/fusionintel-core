# FusionIntel Multi-Tenant Isolation Invariants (Phase 2)

## Hard Invariants
1) No cross-tenant evaluation
2) Tenant-scoped audit segregation
3) Tenant key isolation
4) No shared secret material
5) Explicit tenant identity (tenant_id)
6) Quotas per tenant
7) Deterministic enforcement per tenant

## Overlay Rules (if supported)
- Tenants can only tighten, never weaken global invariants
- Merge: intersection for allowlists, union for denylists, max(strictness) for booleans