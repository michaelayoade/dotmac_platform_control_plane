"""The facility's stable error hierarchy.

Every refusal this package makes is one of these, and each carries the
descriptor path it refused at (``where``) so an operator reading CI output
knows which line of ``deploy/product.toml`` to open. A bare ``ValueError``
would be indistinguishable from a bug in the parser.

The split that matters is the one between :class:`SpecError` (the descriptor is
wrong — a human edits a file) and :class:`DeploymentError` (the descriptor was
fine and the world refused — a human looks at a host). A caller that cannot
tell those apart cannot decide whether to retry.
"""

from __future__ import annotations


class DeploymentFoundationError(Exception):
    """Base of every refusal this package makes."""


# ── Descriptor-side: a human edits a file ───────────────────────────────────


class SpecError(DeploymentFoundationError):
    """The descriptor is malformed, incomplete, or self-contradictory.

    ``code`` is an optional STABLE identifier for the refusal, defaulting to
    empty so every existing raise site is unchanged. It exists because a module
    with more than one refusal has to be testable on WHICH refusal fired, and
    matching on the prose makes the message the contract — after which the
    sentence cannot be improved without breaking a test, and a test that only
    ever saw one wording cannot tell two refusals apart. Assert the code; read
    the prose.
    """

    def __init__(self, message: str, *, where: str = "", code: str = "") -> None:
        self.where = where
        self.code = code
        super().__init__(f"{where}: {message}" if where else message)


class UnknownSchemaError(SpecError):
    """The document declares a schema this version of the facility cannot read.

    Fails closed deliberately. A descriptor written against ``.v2`` may declare
    fields whose absence in ``.v1`` changes behaviour rather than merely losing
    detail, so an older renderer must refuse rather than render a subset.
    """


class UnknownFieldError(SpecError):
    """A key the schema does not define.

    Refused rather than ignored: a typo in ``read_only`` silently disabling the
    read-only filesystem is the exact failure mode this package exists to
    prevent.
    """


class SecretValueError(SpecError):
    """A value that looks like secret material appeared in the descriptor.

    ADR-0009 restated for a checked-in file: the descriptor holds *names* and
    approved pointers. This is raised at parse time, not review time, because a
    secret committed once is a secret that has to be rotated whether or not the
    review caught it.
    """


# ── World-side: a human looks at a host ─────────────────────────────────────


class DeploymentError(DeploymentFoundationError):
    """The descriptor was valid and the deployment refused or failed."""


class LockUnavailableError(DeploymentError):
    """Another deployment holds the exclusive lock."""


class PreconditionFailed(DeploymentError):
    """A gate refused before anything was mutated.

    The important property: nothing has changed, so the caller may resolve the
    stated cause and re-run the identical command.

    ``code`` is an optional STABLE identifier, defaulting to empty so every
    existing raise site is unchanged. Same reason as `SpecError`: a module with
    more than one refusal has to be testable on WHICH refusal fired, and
    matching on prose makes the sentence the contract.
    """

    def __init__(self, message: str, *, code: str = "") -> None:
        self.code = code
        super().__init__(message)


class StepFailed(DeploymentError):
    """A step ran and failed. State may have changed."""

    def __init__(
        self, step: str, message: str, *, exit_code: int | None = None
    ) -> None:
        self.step = step
        self.exit_code = exit_code
        super().__init__(f"{step}: {message}")


class DriftDetected(DeploymentError):
    """Observed state does not match the approved plan."""


class RenderDrift(DeploymentFoundationError):
    """A rendered asset on disk differs from what the descriptor produces.

    Neither side is at fault, so this is neither a ``SpecError`` nor a
    ``DeploymentError``: the answer is always to re-render and commit.
    """
