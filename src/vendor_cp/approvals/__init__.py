"""Versioned approval policy + content-bound approvals (vendor lane slice 2).

`ApprovalPolicyService` owns the *commercial approval* decision (distinct from
operational activation — see `docs/design/contract-service.md`). Policies are
**immutable versions**; approvals are **content-bound** (tied to the exact
version's content hash, so changing the content invalidates prior approvals);
evaluation enforces a **distinct-actor quorum** and **fails closed** when the
policy is missing or ambiguous. Platform-level, vendor-owned.
"""
