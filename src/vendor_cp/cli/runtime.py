"""How a CLI command reaches an owner, and how an owner's refusal comes back.

Three things live here and nothing else does: the session boundary, the
exception translation, and the installed-version lookup.

## The session boundary is the kernel's, unchanged

HTTP routes take a `Session` from `get_platform_db`. The CLI takes the same
session from `dotmac_kernel.db.platform_session`, which is the same runtime with
a different entry shape. There is no second engine, no second URL and no second
transaction owner — deny case D1 applies to a console script exactly as it does
to a route, and the architecture guard scans this package too.

The import is deliberately INSIDE the function. `dotmac_kernel.db` builds its
engine at import time from `DATABASE_URL`, so a module-level import would make
`--help` and `diagnose self` require a configured database to print text. The
clean-install acceptance runs in an environment that has neither.

## Translation carries a verdict; it does not make one

`translate` maps an owner's exception onto this CLI's exit vocabulary. Every
branch is a restatement of something the owner already decided — a refusal stays
a refusal, an absence stays an absence, and a digest that could not be READ is
kept apart from a digest that did not MATCH, because `0.1.0a4` proved how
expensive collapsing those two is. Nothing here decides whether an operation is
allowed.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib import metadata
from typing import TYPE_CHECKING, Final

from vendor_cp.cli.exits import Refusal, refuse

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.orm import Session

#: The installed distribution this CLI belongs to. The name is frozen: the
#: repository was renamed to Platform Control Plane and the DISTRIBUTION was
#: not, so reading `dotmac-platform-control-plane` here would report a package
#: nobody publishes.
DISTRIBUTION: Final[str] = "dotmac-vendor-control-plane"

#: The composed owners whose versions belong in a receipt or a diagnosis. Read
#: from installed metadata, never from a module attribute: the published
#: `dotmac-deployment-control 0.1.0a4` carried `__version__ = "0.1.0a2"`, and a
#: controller fingerprint taken from that attribute would have written the wrong
#: version into the authorization it exists to make auditable.
COMPOSED_DISTRIBUTIONS: Final[tuple[str, ...]] = (
    "dotmac-kernel",
    "dotmac-deployment-control",
    "dotmac-approvals",
    "dotmac-entitlement-allocation",
    "dotmac-commercial-agreements",
    "dotmac-licensing",
    "dotmac-release-catalog",
)


def installed_version(distribution: str) -> str | None:
    """The version recorded in installed metadata, or `None` if not installed.

    `None` rather than a guess. A caller that needs the version to be present
    says so and refuses; a caller that is only reporting prints the absence,
    which is a fact worth seeing.
    """
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def require_version() -> str:
    """This assembly's version, or a refusal naming why it cannot be known.

    Running from a source tree that was never installed is exactly the state in
    which a version literal in the source would have lied confidently, so it is
    an `integrity.*` refusal rather than a default string.
    """
    version = installed_version(DISTRIBUTION)
    if version is None:
        raise refuse(
            "integrity.source_not_installed",
            f"{DISTRIBUTION} has no installed distribution metadata, so this "
            "command cannot report which version it is. Install the wheel; do "
            "not run it from a checkout.",
        )
    return version


@contextmanager
def platform_db() -> Iterator[Session]:
    """The one platform session, borrowed from the kernel for one command."""
    try:
        from dotmac_kernel.db import platform_session
    except Exception as error:  # noqa: BLE001 - reported, never swallowed
        raise refuse(
            "config.missing",
            "the database runtime could not be built — set DATABASE_URL and "
            f"PLATFORM_DATABASE_URL before running this command ({error})",
        ) from error
    with platform_session() as session:
        yield session


#: Owner exception name -> refusal code. Matched on the exception's class name
#: walked up its MRO, so a subclass an owner adds later lands on its parent's
#: verdict instead of falling through to `execution.failed`.
#:
#: `DigestEncodingError` is listed ABOVE `ApprovalRefusedError` and maps to a
#: different code on purpose. In `0.1.0a4` those were one outcome, and a caller
#: supplying the canonical `sha256:` form of the very digest the module froze was
#: told the plan had changed after approval. Keeping them apart here is the
#: caller-side half of the repair `a6` made upstream.
_BY_NAME: Final[tuple[tuple[str, str], ...]] = (
    ("DigestEncodingError", "integrity.digest_unreadable"),
    # The assembly compared what the operator asserted against what the module
    # froze and stopped first. Nobody refused: the owner was never asked, which
    # is why this is a mismatch and not a policy verdict.
    ("DeploymentIdentityMismatch", "integrity.digest_mismatch"),
    ("MigrationRootNotFound", "config.migration_root_unset"),
    ("ApprovalRefusedError", "owner.approval_refused"),
    ("PlanRefusedError", "owner.plan_refused"),
    ("ExpectedStateError", "owner.expected_state"),
    ("TransitionRefusedError", "owner.transition_refused"),
    ("ObservationRefusedError", "owner.transition_refused"),
    ("NotFoundError", "evidence.not_found"),
    ("ConflictError", "owner.conflict"),
    ("ForbiddenError", "owner.forbidden"),
    ("UnauthorizedError", "owner.forbidden"),
    ("BadRequestError", "usage.bad_request"),
    ("RealProviderNotPermittedError", "owner.provider_not_permitted"),
    ("SigningModeNotPermittedError", "owner.provider_not_permitted"),
    ("TransportModeNotPermittedError", "owner.provider_not_permitted"),
    ("SigningKeyUnavailableError", "evidence.capability_absent"),
    ("ProductionConfigurationError", "config.invalid"),
    # `2`, not `4`. A relay with no dispatcher credential is a deployment that
    # was never configured to drain — nothing was attempted and nothing is
    # missing from the database, so "unavailable evidence" would send an
    # operator looking for a row instead of at the environment.
    ("RelayNotConfiguredError", "config.invalid"),
    ("UnknownDeploymentProfileError", "config.invalid"),
    ("CatalogueEvidenceError", "evidence.not_found"),
    ("ReleaseEvidenceConflict", "owner.conflict"),
    ("ReleaseEvidenceError", "usage.bad_request"),
    ("ProductionSecretError", "config.invalid"),
    ("PacketRefused", "owner.readiness_refused"),
    # ── Deployment Control 0.1.0a13's new DIRECT `DeploymentControlError`
    # siblings (`ports.py` ~157-256, `authorization.py`'s
    # `AuthorizationEnvelopeRefusedError`). None subclasses `PlanRefusedError`
    # or any other class already listed, so every one of these fell through to
    # `execution.failed` — "Execution began and failed" — reporting a refusal
    # where nothing executed, which is the worst failure shape this CLI has.
    #
    # `OperationRefusedError` is the one case with an EXISTING code that
    # already says the right thing: it is refused at `ProposePlanCommand`
    # construction, before any state is read — a vocabulary fault, not a
    # decision about a target or a plan — so it is `usage.invalid_argument`
    # exactly like any other malformed argument.
    ("OperationRefusedError", "usage.invalid_argument"),
    # `OperationNotExecutableError` is deliberately NOT a subclass of
    # `OperationRefusedError` (the module's own docstring: the two say
    # opposite things about the same word), so it needs its own code rather
    # than inheriting `usage.invalid_argument` by MRO. Raised only at the
    # signing fence, where the word IS a member of the vocabulary and the
    # executor has not published support for it — an owner decision.
    ("OperationNotExecutableError", "owner.operation_not_executable"),
    ("ExecutionPlanBindingError", "owner.execution_plan_binding_refused"),
    ("DescriptorBindingError", "owner.descriptor_binding_refused"),
    ("ImageSetRefusedError", "evidence.image_set_unreadable"),
    # "the capability is absent" is exactly what `SigningKeyUnavailableError`
    # already means above, and it is exactly what `AuthorizationEnvelopeRefusedError`
    # means on the only path this assembly can reach: `authorize_deployment`
    # never supplies a signer (signer identities are unminted by design,
    # `vendor_cp.deployment.signers`), so `request_rollout` always raises this
    # with code ABSENT.
    ("AuthorizationEnvelopeRefusedError", "evidence.capability_absent"),
    # Two independently-sourced digest readings disagree, or the evidence
    # document is not trustworthy enough to hand one out of — the same "this
    # is not what it claims to be" shape `DeploymentIdentityMismatch` above
    # already carries `integrity.digest_mismatch` for.
    ("CandidateArtifactRefusedError", "integrity.digest_mismatch"),
    # ── `vendor_cp.deployment.candidate`'s own refusals. `render_candidate`
    # had ZERO callers before the a13 repin gave `deployment propose` one, so
    # neither of these could previously reach this CLI at all.
    #
    # `candidate.py`'s own docstring names the code for this one: "its
    # absence is a runtime answer (`evidence.tool_absent`) ... exactly as
    # `vendor_cp.recovery.bundle` already treats it."
    ("FoundationAbsent", "evidence.tool_absent"),
    # `CandidateRefused`'s own docstring: "This assembly compared what it was
    # handed against what the receipt and the registry say, and stopped
    # first" — word for word the same shape `DeploymentIdentityMismatch`
    # above is mapped for, so it gets the same code.
    ("CandidateRefused", "integrity.digest_mismatch"),
    # `vendor_cp.deployment.adapter`'s own policy: an `authorization_expires_at`
    # requesting a window longer than the configured ceiling.
    ("AuthorizationWindowRefused", "owner.authorization_window_refused"),
)


def translate(error: Exception) -> Refusal:
    """Carry an owner's exception out as this CLI's verdict.

    Walks the MRO rather than checking `type(error).__name__`, so a module that
    introduces `PlanSupersededError(PlanRefusedError)` next release is refused
    as a plan refusal instead of silently becoming an execution failure.
    """
    if isinstance(error, Refusal):
        return error
    names = {klass.__name__ for klass in type(error).__mro__}
    for name, code in _BY_NAME:
        if name in names:
            return refuse(code, str(error) or name)
    return refuse("execution.failed", f"{type(error).__name__}: {error}")


__all__ = [
    "COMPOSED_DISTRIBUTIONS",
    "DISTRIBUTION",
    "installed_version",
    "platform_db",
    "require_version",
    "translate",
]
