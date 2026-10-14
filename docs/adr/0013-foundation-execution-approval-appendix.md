# ADR-0013 appendix: Foundation execution approval composition

This implements the already-ratified approval tuple and synchronous barrier; it
adds no approval policy, expiry policy, operational authorization or profile
admission. Source preparation is separate from hosted acceptance and adoption.

`vendor_cp.deployment.foundation_approval` owns the distinct subject type
`foundation_execution_plan.v1`. Its subject ID is
`v1|plan UUID|foundation_execution|operation|execution-plan digest`. Control's
snapshot digest is the separate approval content digest. The subject rejects
approval-exempt plans and unsupported executor operations. Control continues to
validate the stored purpose against its frozen snapshot at owner transitions;
`PlanView.purpose` is only the service's preliminary coordinate check.

Opening a request uses the frozen policy/version and authenticated requester.
Approval carries Approvals' held request reference, completion time and policy;
it copies no approver identity. Rollout requires explicit authorization expiry
and the startup signer. Dispatch requires the independently bound dispatch signer
and authorization verifier. Approval, rollout and dispatch never commit. Their
caller holds the shared Approvals lock through its single commit. Immutable
subject/content/policy and carried-decision coordinates are read again inside
the hold before invoking Control.

The import-light host adapter accepts the same barrier as a startup dependency
on `FoundationV3Sources.held_transition`. A missing binding refuses with
`DispatchApprovalSubjectUnavailable`. Session A resolves, commits and closes
before Foundation verifies the candidate/installed pair. Session B compares the
observed carried decision with Control, takes a fresh Approvals hold, invokes
Control's sole finalizer and commits once. A prior hold or status read supplies
no launch authority. Committed-consumption lookup remains Control's owner API.

The existing approval router now recognizes the Foundation subject. Its
classifier validates event coordinates and establishes permanent withdrawn
standing under the Approvals shared lock before taking a Control lock. It uses
public `revoke_plan_approval`; it neither cancels deployment nor revokes issuer
purpose authorizations. Sibling decisions are `not_carried`; existing revocation
references remain immutable. Domain consequence and the existing append-only
terminal outcome share the router transaction. Exact event replay and changed
payload behavior remain the router's existing owner contract. Database errors
are redacted by the router and roll the delivery transaction back.

Coding evidence is the exact Control a17 release source
`574418944d35ddf3559d17e59e9184b5f545ebe4` and CP's pinned Approvals a8 adapter.
This is not an installed-wheel or production proof. The new PostgreSQL suite
covers real request/decision/approval, shared-lock withdrawal blocking,
withdrawal-first refusal, sibling non-carriage, owner revocation and outcome
replay/conflict. Host tests cover the Session-A/Session-B choreography and
startup-barrier refusal. All execution tests must run on GitHub-hosted CI;
none were run locally during preparation.

Outstanding integrated acceptance includes real signed rollout/dispatch and
Foundation finalization with both withdrawal lock orderings at each boundary,
autocommit refusal, consumed-dispatch replay and crash lookup against the exact
permitted artifact. The actual canonical profile/admission prerequisite must
be supplied before a positive
proposal is exposed. This appendix does not discharge that prerequisite or
claim a receipt-producing deployment.

`vendor_cp.deployment.runtime.build_foundation_v3_providers` is the concrete
startup factory: it imports the installed owners' public functions and types,
derives both Foundation trust roots from the resolved Control context without
rewriting key encoding, and always binds the real Foundation approval hold.
Its interface offers no alternative barrier or request-selected owner functions.
The architecture guard checks the narrow finalizer-reference exemption against
this binding. The installed CP conformance lane uses the factory itself.

The required PostgreSQL job builds an exact-source Foundation test wheel,
installs the built CP wheel into its complete pinned dependency closure, and
runs host-admission and renderer conformance outside the checkout. Its named
JUnit gate rejects omitted, duplicated or skipped cases. The test-only
Foundation artifact is not a candidate allocation, eligible production pin or
profile admission. Real production service callers, canonical profile/receipt,
shared executor/effects composition and deployment/recovery acceptance remain
separate requirements; green source tests cannot replace them.
