# Gate-0 approved-start capture values

`gate0_capture` encodes the existing CP owner capture for the selected IDP3
issuer / NS3 attester design. It adds no approval authority, signature, ledger,
transport, CLI command or live loader. A successfully decoded capture is an
**unauthenticated value**. A digest establishes equality; the future trusted
management loader must independently authenticate delivery and the expected
coordinates before constructing NS3 admission. Neither runner stdin nor a
capture's own metadata can supply that independent expectation.

## Wire contract

`Gate0ApprovedStartCapture.v1` is canonical ASCII JSON, at most 65,536 bytes.
Canonicalization uses the existing CP `canonical` owner: sorted keys, compact
separators, ASCII escaping, no nonfinite numbers. The parser rejects duplicate
keys, unknown/missing fields, wrong shapes/types, noncanonical bytes and
noncanonical UUID/digest/base64 encodings. The exact top-level fields are:

- `schema`: exactly `Gate0ApprovedStartCapture.v1`.
- `frozen_window_b64`: standard padded canonical base64 of the exact canonical
  `Gate0IssuerWindow.v1` bytes, bounded by the existing 32,768-byte window limit.
- `window_digest`: the existing CP frozen-window SHA-256 digest.
- `plan_id`, `plan_digest`, `target_id`, `environment`.
- `approval_request_id`, `approval_policy_code`, `approval_policy_version`.
- `descriptor_digest`, `authorized_image_digests`.
- `operation`: exactly the 17 existing `AdmittedOperation` fields, including
  `phase='issue'`, `authorization_digest=null`, `authorization_issued_at=null`.

The ordered image list has at most 64 canonical digest strings; empty means the
owner declared no images. The codec neither sorts/deduplicates that list nor
invents a new image policy. The issuer reader already refuses an undeclared
image set. Existing `FrozenIssuerWindow.parse`, `AdmissionExpectation` and
`ApprovedWindowBinding` validate the frozen terms. Top-level plan ID/digest
must equal the operation; target/policy/controller/run/window/descriptor and
execution bindings must agree with the existing frozen window validators.
Foundation's `execution_plan_digest` remains unchanged and opaque.

The full capture digest is `sha256:` plus lowercase SHA-256 hex over all encoded
capture bytes. It is outside the envelope to avoid a self-hash. Required
`CaptureCoordinates` contain that digest, window digest, plan UUID/digest,
target UUID and approval-request UUID. `decode_capture(encoded, expected=...)`
compares every coordinate; absent or differently typed expectations refuse.
The whole digest binds the remaining fields, including image order and policy.
Expected coordinates provided alongside untrusted bytes are not an independent
trust source, even when all comparisons pass.

No `WindowFreshness`, monotonic origin/deadline, runtime, callback, token,
private key or future authorization is serialized. `UnauthenticatedCapture`
contains the reconstructed existing binding with `window_freshness=None`.
Decoding performs no current approval/ledger lookup, expiry admission or
signing. Old bytes can still decode after withdrawal: this is intentional data
parsing, never current standing. NS3's existing `ApprovedAtStartAdmission`
maps authenticated absolute expiry once to its own startup clocks; IDP3
continues to recheck actual held approval at each point of use.

## Concrete issuer export

`export_approved_start(reader, configured_plans)` accepts the exact concrete
`OwnerWindowReader` and a trusted tuple of 1–4 unique configured plan UUIDs.
It validates the complete selection before I/O and calls
`reader.read('issue', plan_id)` itself for every plan. A generic callback,
subclass/provider replacement or caller-provided binding cannot select the
export path. It returns immutable `PublicCapture(encoded, coordinates)` values;
there is no public binding-to-export endpoint.

The existing reader supplies the actual public Control frozen snapshot under
CP's canonical exact-content Approvals hold. Every returned plan must match its
selected UUID. Original reader/window monotonic bounds are checked before
return, and a failed member returns no partial tuple. Four captures bound total
payload to 262,144 bytes. Each member records approval at its own held read;
there is no simultaneous batch hold or assertion that approval still stands.
No lock survives the read. Management publication/descriptor writes and their
I/O deadlines remain outside this pure export-result boundary.

## Authored evidence and remaining inputs

Hosted unit vectors cover canonical roundtrip, required independent coordinates,
whole-hash/coordinate substitutions, rehashed malformed/internal contradictions,
unknown/duplicate fields, shapes/types, ASCII/base64/size limits, image bounds,
issue-only terms, selected-plan limits, four-plan positive, no partial export and
original freshness refusal. The separate PostgreSQL test uses actual public
Control plans and CP Approvals decisions/holds, demonstrates that changed
mutable desired state cannot change the frozen export, and refuses re-export
after a real withdrawal. Inputs/actors/keys are explicitly synthetic; it does
not prove a live human decision or authenticated management delivery.

Required hosted strict mypy and test execution remain pending for this source
slice. Actual capture transport/authentication, protected installation location,
independent expected-coordinate delivery, launch/session serialization,
role-local custody, qualified DB/driver and Bao transport, publication/recovery
and host installation remain separate inputs. No source fixture is deployable,
no Gate-0 acceptance follows, and shared Contabo/host-root residuals remain open.
