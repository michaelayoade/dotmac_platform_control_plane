"""Build the `ApplicationFoundationProfile` document THIS artifact carries.

The producing half of the pair whose reading half is
`vendor_cp.deployment.profile_readback`. That verifier shipped first and
deliberately: it refuses `DOCUMENT_ABSENT` today, which is the honest state of
the artifact, and a refusal that turns into a different verdict when the
document lands is the evidence the document is CONSUMED rather than merely
shipped. This module is what makes that transition happen.

## A concern is bound because a provider ANSWERED

Nothing below writes a concern into the document because a literal said so. For
every concern, the builder RESOLVES its providers in the environment the image
actually has — `importlib.import_module` and `getattr`, against the installed
distributions — and refuses to emit anything if a symbol is missing. A kernel
repin that removes `write_platform_audit_event` does not produce a profile
claiming `audit_telemetry`; it fails the image build.

Three facts per provider, and none of them is typed in:

* the **version** comes from `importlib.metadata`, i.e. from what the INSTALLER
  recorded — the same rule `vendor_cp.identity` already holds this assembly to
  after `dotmac-deployment-control 0.1.0a4` shipped correct bytes with a wrong
  self-report;
* the **coordinate** comes from `poetry.lock`'s recorded wheel hash, the
  checked-in immutable record, or — for a provider this assembly owns — from the
  peeled commit the image was built at;
* the two are CROSS-CHECKED. A distribution whose installed version disagrees
  with the version the lock records is refused, because a coordinate read from
  the lock would then name a wheel that is not the one in this image.

## Where this runs, and why it is not a Dockerfile heredoc

`python -m vendor_cp.deployment.profile`, inside the builder stage, from the
INSTALLED wheel. The document is therefore produced by the same bytes it
describes. Writing it as an inline script in the Dockerfile would have made the
whole thing a literal in a build file — the exact shape "bound because a
provider answered" exists to rule out — and nothing would have type-checked,
linted or been testable.

## Two concerns are left UNBOUND, by decision rather than by omission

The document names them and says why, so an incomplete profile explains itself
instead of merely being short:

* **`request_evidence_context`** — ruled 2026-09-04, implementation ownership is
  `dotmac-kernel`'s, extracted product-first from ERP. *"Do not declare the
  profile provider until an installed artifact and real assembly wiring consume
  it."* The slot is built; filling it from this side would be the inert binding
  the gate refuses.
* **`integration`** — the verifier accepts a proven absence through
  `IntegrationSurfaceAbsenceProofV1`, and that type lives in
  `dotmac-deployment-foundation`, which this assembly deliberately does not
  depend on and which the acceptance battery's step 17 proves is NOT in the
  image. So the proof cannot be CONSTRUCTED here. Hand-writing its JSON would
  re-implement another repository's type, and the whole value of that type is
  the refusals its constructor performs — refusals that, as `profile_readback`
  says, do not travel in a document. Pinning Foundation even as a build-only
  tool is a composition decision this repository has not taken. Flagged, not
  invented.

So `verify_embedded_profile` returns `CONCERNS_INCOMPLETE` naming exactly those
two. That is the correct verdict for this artifact, and it is the first one that
has ever been computed against real bytes rather than against a `tmp_path`
fixture.

## The digest is implemented AGAIN here, on purpose

`profile_readback.canonical_profile_digest` is a SPECIFICATION, and its own
docstring says the builder implements it separately: sharing an encoder would
make the digest a statement that one function agrees with itself.
:func:`profile_digest` below is that second implementation, and
`tests/unit/test_profile_document.py` drives both over documents chosen to
separate them — non-ASCII, nested, reordered keys — rather than asserting they
agree on one easy case.

What IS imported from the verifier is vocabulary, not computation: the contract
string and the thirteen slot names. Two spellings of a wire name is a bug with
no upside, and importing them one-directionally means a fourteenth slot added
there fails the build here instead of silently producing a short document.

## `canonical_inventory_digest` is not used, and that is worth saying

The only thing that needed it was the integration absence proof, which this
builder does not produce. So no second implementation of it was written and the
local one was not hardened further. Its ownership is routed to Foundation; if a
proof is ever produced here, that dependency has to be settled first.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Final

from vendor_cp.deployment.profile_readback import (
    FOUNDATION_CONCERNS,
    PROFILE_CONTRACT,
)
from vendor_cp.identity import DISTRIBUTION

__all__ = [
    "ASSEMBLY",
    "CONCERN_SPECS",
    "ConcernSpec",
    "ProfileBuildRefusal",
    "build_profile_document",
    "main",
    "profile_digest",
    "resolve_probe",
]

#: The marker a spec uses for "this assembly provides it". Not the distribution
#: NAME, because the name is `vendor_cp.identity.DISTRIBUTION`'s to answer and a
#: second spelling of it here is exactly the literal that module exists to end.
ASSEMBLY: Final = "<assembly>"

#: A peeled commit, and nothing else. `scripts/deploy_production.sh` already
#: refuses anything but this shape when it reads the revision back off the
#: image, so a document built at `SOURCE_REVISION=unknown` would describe an
#: artifact that deployment would then reject — better to fail at build.
_PEELED_COMMIT_LENGTH: Final = 40
_HEX: Final = frozenset("0123456789abcdef")


class ProfileBuildRefusal(RuntimeError):
    """The document was not built. Nothing was written."""


@dataclass(frozen=True, slots=True)
class ConcernSpec:
    """One `ApplicationFoundationProfile` slot, and how to ANSWER it.

    `probes` are `module` or `module:symbol` paths that must resolve in the
    installed environment. They are the whole reason a binding in the emitted
    document means something: a spec whose provider is gone cannot produce one.
    """

    concern: str
    distributions: tuple[str, ...]
    probes: tuple[str, ...]
    consumer: str
    #: Non-empty for a slot deliberately left unfilled. Such a spec MUST carry
    #: no probes and no distributions: a reason plus a provider is a slot that
    #: has not decided which it is.
    unbound_reason: str = ""

    def __post_init__(self) -> None:
        if self.unbound_reason:
            if self.probes or self.distributions:
                raise ValueError(
                    f"{self.concern}: a concern declared unbound may not also "
                    "name a provider. A reason beside a binding is a slot that "
                    "has not decided which it is"
                )
            return
        if not self.probes:
            raise ValueError(
                f"{self.concern}: a bound concern needs at least one probe. "
                "Without one it is bound because this table says so, which is "
                "the literal-in-a-fixture shape the builder exists to refuse"
            )
        if not self.distributions:
            raise ValueError(f"{self.concern}: a bound concern needs a coordinate")
        if not self.consumer.strip():
            raise ValueError(
                f"{self.concern}: a provider nothing discovers is inert, so a "
                "binding must name its runtime consumer"
            )


#: THE THIRTEEN SLOTS. Coverage is asserted against `FOUNDATION_CONCERNS`, so a
#: slot added to the verifier fails the build here rather than quietly producing
#: a document that is short by one.
CONCERN_SPECS: Final[tuple[ConcernSpec, ...]] = (
    ConcernSpec(
        concern="identity_session",
        distributions=("dotmac-kernel",),
        probes=(
            "dotmac_kernel.platform_auth:authenticate_platform_request",
            "dotmac_kernel.platform_auth:issue_platform_token",
            "dotmac_kernel.platform_web:PLATFORM_WEB_SURFACE",
        ),
        consumer="every platform route and the console facet; the browser "
        "session is issued and read through this one seam",
    ),
    ConcernSpec(
        concern="authorization",
        distributions=("dotmac-kernel",),
        probes=(
            "dotmac_kernel.platform_auth:require_platform_admin",
            "dotmac_kernel.platform_auth:require_platform_web_auth",
        ),
        consumer="the route guard on every platform API and browser route",
    ),
    ConcernSpec(
        concern="persistence_migrations",
        distributions=("dotmac-kernel", ASSEMBLY),
        probes=(
            "dotmac_kernel.migrations:versions_dir",
            "vendor_cp.migrations:deploy_config",
            "vendor_cp.migrations:composed_version_locations",
        ),
        consumer="`dotmac-platform admin migrate`, which composes eight "
        "lineages and applies only their composed heads",
    ),
    ConcernSpec(
        concern="settings_secrets",
        distributions=(ASSEMBLY,),
        probes=(
            "vendor_cp.config:vendor_settings",
            "vendor_cp.config:validate_runtime_configuration",
            "vendor_cp.production_secrets",
        ),
        consumer="boot configuration and the OpenBao materializer",
    ),
    ConcernSpec(
        concern="audit_telemetry",
        distributions=("dotmac-kernel",),
        probes=("dotmac_kernel.audit:write_platform_audit_event",),
        consumer="every declared `vendor.*` action; kernel 0026 makes the row "
        "immutable and `data_governance` withholds the DELETE",
    ),
    ConcernSpec(
        concern="health_runtime_admission",
        distributions=(ASSEMBLY, "dotmac-kernel"),
        probes=(
            "vendor_cp.readiness.service",
            "vendor_cp.deployment_profile:admit_surfaces",
            "dotmac_kernel.app_factory:create_app",
        ),
        consumer="`/health/ready` under every profile, and the boot-time "
        "surface admission `build_spec` runs before key custody",
    ),
    ConcernSpec(
        concern="worker_execution",
        distributions=("dotmac-kernel", ASSEMBLY),
        probes=(
            "dotmac_kernel.messaging.platform_worker:claim_platform_batch",
            "dotmac_kernel.messaging.platform_worker:RelayPolicy",
            "vendor_cp.relay.runner",
        ),
        consumer="`vendor_cp.relay.runner` — the composed relay service. Before "
        "it existed this concern had a provider in the image and nothing that "
        "discovered it, which is inert by the gate's own definition",
    ),
    ConcernSpec(
        concern="edge_security",
        distributions=("dotmac-kernel",),
        probes=(
            "dotmac_kernel.middleware.csrf:require_csrf",
            "dotmac_kernel.middleware.security_headers",
            "dotmac_kernel.middleware.rate_limit",
        ),
        consumer="`require_csrf` on every composed browser route; headers and "
        "rate limiting are mounted by `create_app`",
    ),
    ConcernSpec(
        concern="api_web_interaction",
        distributions=("dotmac-kernel", ASSEMBLY),
        probes=(
            "dotmac_kernel.app_factory:create_app",
            "dotmac_kernel.web_surfaces",
            "vendor_cp.main:app",
        ),
        consumer="the composed ASGI application this image's CMD serves",
    ),
    ConcernSpec(
        concern="deployment_recovery",
        distributions=("dotmac-deployment-control", ASSEMBLY),
        probes=(
            "dotmac_deployment_control:versions_dir",
            "dotmac_deployment_control:module",
            "vendor_cp.recovery.bundle",
            "vendor_cp.recovery.capture",
        ),
        consumer="the recovery bundle path and `dotmac-platform recovery "
        "capture-sql`",
    ),
    ConcernSpec(
        concern="request_evidence_context",
        distributions=(),
        probes=(),
        consumer="",
        unbound_reason="ruled 2026-09-04: implementation ownership is "
        "`dotmac-kernel`'s, extracted product-first from ERP's trusted-proxy "
        "behaviour, with ERP the first adopter. Do not declare the profile "
        "provider until an installed artifact and real assembly wiring consume "
        "it. The slot is built and this verifier already judges it; filling it "
        "from this side would be the inert binding the gate refuses",
    ),
    ConcernSpec(
        concern="data_governance",
        distributions=(ASSEMBLY,),
        probes=(
            "vendor_cp.data_governance:enforce_retention",
            "vendor_cp.data_governance:GOVERNED_TABLES",
            "vendor_cp.data_governance:CONTRACT",
        ),
        consumer="`dotmac-platform admin migrate` — `alembic/env.py` calls "
        "`enforce_retention` inside the composed upgrade's single transaction, "
        "so an unclassified table rolls the deploy back",
    ),
    ConcernSpec(
        concern="integration",
        distributions=(),
        probes=(),
        consumer="",
        unbound_reason="the verifier accepts a proven absence only through "
        "`IntegrationSurfaceAbsenceProofV1`, which lives in "
        "`dotmac-deployment-foundation` — a distribution this assembly "
        "deliberately does not depend on and which acceptance step 17 proves is "
        "absent from this image. The proof cannot be CONSTRUCTED here, and "
        "hand-writing its JSON would re-implement another repository's type "
        "while discarding the constructor refusals that are the whole point of "
        "it. Pinning Foundation as a build-only tool is a composition decision "
        "this repository has not taken",
    ),
)


def profile_digest(document: Mapping[str, object]) -> str:
    """This artifact's own implementation of the canonical profile digest.

    A SECOND implementation of the specification
    `profile_readback.canonical_profile_digest` states, written without
    importing it: UTF-8 JSON, keys sorted, no insignificant whitespace,
    non-ASCII kept as itself, with `profile_digest` removed because a field
    cannot be an input to its own value.

    Sharing the encoder would make the verifier's digest check a statement that
    one function agrees with itself. Two implementations that must agree is the
    check; one function called twice is not.
    """
    payload = {
        key: document[key] for key in sorted(document) if key != "profile_digest"
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def resolve_probe(probe: str) -> object:
    """Import `module` or `module:symbol`, or refuse by name.

    This is where a binding stops being a claim. `importlib` answers from the
    INSTALLED environment, so inside the image it answers about the wheel that
    was installed one build instruction earlier.
    """
    module_name, _, symbol = probe.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as error:  # noqa: BLE001 - every failure is the same answer
        raise ProfileBuildRefusal(
            f"{probe}: {module_name} does not import in this environment "
            f"({error.__class__.__name__}: {error}). A concern is bound because "
            "a provider answered; this one did not"
        ) from error
    if not symbol:
        return module
    try:
        return getattr(module, symbol)
    except AttributeError as error:
        raise ProfileBuildRefusal(
            f"{probe}: {module_name} imports but has no {symbol!r}. The provider "
            "moved or was removed, and a profile claiming this concern would be "
            "describing an artifact that cannot serve it"
        ) from error


def _locked_wheels(lock_path: Path) -> dict[str, tuple[str, str]]:
    """`distribution -> (version, wheel sha256)` from the checked-in lock.

    The lock is the immutable record this repository already treats as
    authoritative for coordinates. Reading it here rather than re-measuring is
    the point: a coordinate re-derived from the installed files would be a
    number this build invented, and a coordinate is only useful if somebody
    else can look it up.
    """
    try:
        parsed = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ProfileBuildRefusal(
            f"{lock_path} is missing or unreadable ({error.__class__.__name__}), "
            "so no provider can be given an immutable coordinate"
        ) from error

    found: dict[str, tuple[str, str]] = {}
    for package in parsed.get("package", ()):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        wheels = [
            str(entry.get("hash", ""))
            for entry in package.get("files", ())
            if isinstance(entry, dict) and str(entry.get("file", "")).endswith(".whl")
        ]
        if name and version and len(wheels) == 1:
            found[name] = (version, wheels[0])
    if not found:
        raise ProfileBuildRefusal(
            f"{lock_path} recorded no single-wheel package at all. An empty "
            "coordinate source produces a document with no coordinates and no "
            "complaint, which is the vacuous pass this refuses"
        )
    return found


def _provider_record(
    distribution: str,
    *,
    locked: Mapping[str, tuple[str, str]],
    source_revision: str,
) -> dict[str, str]:
    """One provider's version and immutable coordinate, cross-checked."""
    if distribution == ASSEMBLY:
        return {
            "distribution": DISTRIBUTION,
            "version": _installed_version(DISTRIBUTION),
            "coordinate": source_revision,
            "coordinate_kind": "peeled_commit",
        }
    installed = _installed_version(distribution)
    if distribution not in locked:
        raise ProfileBuildRefusal(
            f"{distribution} is installed at {installed} and the lock records no "
            "single wheel for it, so this build can offer no immutable "
            "coordinate for a provider it is about to claim"
        )
    locked_version, wheel = locked[distribution]
    if locked_version != installed:
        raise ProfileBuildRefusal(
            f"{distribution} is installed at {installed} and the lock records "
            f"{locked_version}. The coordinate would name a wheel that is not "
            "the one in this image — the exact disagreement a coordinate exists "
            "to make impossible"
        )
    return {
        "distribution": distribution,
        "version": installed,
        "coordinate": wheel,
        "coordinate_kind": "wheel_sha256",
    }


def _installed_version(distribution: str) -> str:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError as error:
        raise ProfileBuildRefusal(
            f"{distribution} is not installed in this environment. A profile "
            "naming it as a provider would describe an image that does not "
            "carry it"
        ) from error


def _sole_wheel_digest(dist_dir: Path) -> str:
    """The digest of the wheel this image installs, hashed from the file.

    Measured here rather than read out of `distributions.json`, so the verifier
    comparing the document's `wheel_sha256` against that record is comparing two
    independent readings of the same bytes rather than one file with itself.
    """
    wheels = sorted(path for path in dist_dir.glob("*.whl") if path.is_file())
    if len(wheels) != 1:
        raise ProfileBuildRefusal(
            f"{dist_dir} holds {len(wheels)} wheels; exactly one is required, "
            "because a profile binds to THE artifact and picking one of several "
            "would be choosing which artifact to describe"
        )
    return "sha256:" + hashlib.sha256(wheels[0].read_bytes()).hexdigest()


def _require_peeled(source_revision: str) -> str:
    revision = source_revision.strip().lower()
    if len(revision) != _PEELED_COMMIT_LENGTH or not set(revision) <= _HEX:
        raise ProfileBuildRefusal(
            f"source revision {source_revision!r} is not a peeled 40-character "
            "commit. `scripts/deploy_production.sh` refuses the same shape when "
            "it reads the revision back off the image, so a document built from "
            "a branch name would describe an artifact the deploy then rejects"
        )
    return revision


def _require_full_coverage(specs: Sequence[ConcernSpec]) -> None:
    declared = [spec.concern for spec in specs]
    if len(declared) != len(set(declared)):
        raise ProfileBuildRefusal(f"a concern is specified twice: {sorted(declared)}")
    missing = [name for name in FOUNDATION_CONCERNS if name not in set(declared)]
    if missing:
        raise ProfileBuildRefusal(
            f"no spec covers {missing}. A slot with no spec produces a document "
            "that is short by one and says nothing about why"
        )
    unknown = sorted(set(declared) - set(FOUNDATION_CONCERNS))
    if unknown:
        raise ProfileBuildRefusal(
            f"{unknown} are not concerns this profile has slots for. The "
            "verifier ignores them, so a document carrying one would claim "
            "something nobody reads"
        )


def build_profile_document(
    *,
    source_revision: str,
    dist_dir: Path,
    lock_path: Path,
    specs: Sequence[ConcernSpec] = CONCERN_SPECS,
) -> dict[str, object]:
    """The document, or a refusal. Deterministic: nothing here reads a clock.

    A timestamp would make two builds of identical source produce different
    digests, and the digest is how anyone tells one profile from another.
    """
    _require_full_coverage(specs)
    revision = _require_peeled(source_revision)
    locked = _locked_wheels(lock_path)

    concerns: dict[str, object] = {}
    unbound: dict[str, str] = {}
    for spec in specs:
        if spec.unbound_reason:
            unbound[spec.concern] = spec.unbound_reason
            continue
        for probe in spec.probes:
            resolve_probe(probe)
        concerns[spec.concern] = {
            "providers": [
                _provider_record(distribution, locked=locked, source_revision=revision)
                for distribution in spec.distributions
            ],
            "probes": list(spec.probes),
            "consumer": spec.consumer,
        }

    document: dict[str, object] = {
        "contract": PROFILE_CONTRACT,
        "source_revision": revision,
        "wheel_sha256": _sole_wheel_digest(dist_dir),
        "concerns": concerns,
        # Named rather than merely absent. A short document that explains its
        # own shortfall is reviewable; one that is simply short is a mystery
        # the next reader has to reconstruct.
        "unbound_concerns": unbound,
    }
    document["profile_digest"] = profile_digest(document)
    return document


def render(document: Mapping[str, object]) -> str:
    """The bytes that travel in the image. Stable, sorted, newline-terminated."""
    return (
        json.dumps(dict(document), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m vendor_cp.deployment.profile",
        description="Build the ApplicationFoundationProfile document for this build.",
    )
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--dist-dir", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        document = build_profile_document(
            source_revision=args.source_revision,
            dist_dir=args.dist_dir,
            lock_path=args.lock,
        )
    except ProfileBuildRefusal as refusal:
        print(f"profile build refused: {refusal}", file=sys.stderr)
        return 1

    args.output.write_text(render(document), encoding="utf-8")
    bound = sorted(dict(document["concerns"]))  # type: ignore[call-overload]
    unbound = sorted(dict(document["unbound_concerns"]))  # type: ignore[call-overload]
    print(
        f"{args.output}: {len(bound)} of {len(FOUNDATION_CONCERNS)} concerns "
        f"bound, {len(unbound)} declared unbound ({', '.join(unbound)}), "
        f"digest {document['profile_digest']}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    raise SystemExit(main())
