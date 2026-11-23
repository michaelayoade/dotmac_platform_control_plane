"""Typed refusals for the target-side Foundation bindings (Gate 2, E6).

Every refusal here names a THING (an environment variable, a document kind, a
purpose, a limit) and never a value: no DSN, path, key, fingerprint or token is
ever placed in a message. The `code` is the machine-readable half; a message is
prose for a reader and is never matched on.

`FoundationBindingsUnavailable` lives here, not in `foundation_bindings`, so
that the leaf modules this assembly composes (clock, scoped DSN, verification
identities, control security) can raise the very type discovery already
surfaces loudly, without importing the module that imports them. It is
re-exported from `foundation_bindings` for every existing caller.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["FoundationBindingsUnavailable", "TargetRefusal"]


class TargetRefusal(StrEnum):
    """Why target-side composition refused. Stable identifiers, not prose."""

    UNSPECIFIED = "target_bindings_unavailable"
    PLACEMENT_UNSUPPORTED = "target_placement_unsupported"
    FOUNDATION_MISSING = "target_foundation_not_installed"
    CONSUMPTION_DSN_MISSING = "consumption_dsn_missing"
    CONSUMPTION_DSN_MALFORMED = "consumption_dsn_malformed"
    CONSUMPTION_DSN_NOT_SCOPED = "consumption_dsn_not_scoped"
    GENERAL_DSN_PRESENT = "general_dsn_present_on_target"
    CONSUMPTION_ROLE_OVERBROAD = "consumption_role_overbroad"
    CONSUMPTION_ROLE_UNVERIFIABLE = "consumption_role_unverifiable"
    CLOCK_UNAVAILABLE = "database_clock_unavailable"
    CLOCK_SKEW_EXCEEDED = "clock_skew_exceeded"
    CLOCK_SKEW_LIMIT_INVALID = "clock_skew_limit_invalid"
    VERIFICATION_IDENTITY_MISSING = "verification_identity_missing"
    VERIFICATION_IDENTITY_REFUSED = "verification_identity_refused"
    EVIDENCE_POLICY_INCOMPLETE = "release_evidence_policy_incomplete"
    CONTROL_SECURITY_REFUSED = "control_security_install_refused"
    CUSTODY_NOT_CONFIGURED = "custody_not_configured"
    MATERIALS_REFUSED = "materials_refused"
    #: Build-once generic deploy (P-CP1 5a): the params.env / legacy-file checks.
    PARAMS_ENV_MALFORMED = "params_env_malformed"
    PARAMS_ENV_DIGEST_MISMATCH = "params_env_digest_mismatch"
    DOTENV_PRESENT = "dotenv_present"
    COMPOSE_OVERRIDE_PRESENT = "compose_override_present"
    LEGACY_ENV_SHA_MISMATCH = "legacy_env_sha_mismatch"
    LEGACY_ENV_NOT_BOUND = "legacy_env_not_bound"
    LEGACY_ENV_MISSING = "legacy_env_missing"
    IMAGE_SOURCE_INVALID = "image_source_invalid"


class FoundationBindingsUnavailable(RuntimeError):
    """Startup composition cannot be completed. Sanitized: names only."""

    def __init__(
        self,
        message: str,
        *,
        code: TargetRefusal = TargetRefusal.UNSPECIFIED,
    ) -> None:
        super().__init__(message)
        self.code = code
