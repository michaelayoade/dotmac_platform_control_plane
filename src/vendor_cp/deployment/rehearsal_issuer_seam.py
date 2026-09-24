"""Source-only inputs for a later, protected Control a14 rehearsal composition.

This leaf neither interprets signed harness evidence nor issues authorization.
The composing application will pass the request and opaque evidence to Control.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RehearsalIssuerCommand:
    """Only the caller-controlled fields accepted by Control's a14 request."""

    command_id: str
    plan_id: UUID
    actor_ref: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.command_id, str):
            raise TypeError("command_id must be a string")
        if not isinstance(self.plan_id, UUID):
            raise TypeError("plan_id must be a UUID")
        if self.actor_ref is not None and not isinstance(self.actor_ref, str):
            raise TypeError("actor_ref must be a string when present")
        if not self.command_id.strip():
            raise ValueError("command_id must not be blank")
        if self.actor_ref is not None and not self.actor_ref.strip():
            raise ValueError("actor_ref must not be blank")

    def to_control_request(self) -> Mapping[str, str | UUID]:
        """Return exactly Control's request fields in a read-only mapping."""
        request: dict[str, str | UUID] = {
            "command_id": self.command_id,
            "plan_id": self.plan_id,
        }
        if self.actor_ref is not None:
            request["actor_ref"] = self.actor_ref
        return MappingProxyType(request)


@dataclass(frozen=True, slots=True)
class RehearsalIssuerInvocation:
    """Carry signed harness evidence by identity, without examining it."""

    command: RehearsalIssuerCommand
    harness_evidence_document: object

    def __post_init__(self) -> None:
        if type(self.command) is not RehearsalIssuerCommand:
            raise TypeError("command must be a RehearsalIssuerCommand")

    def to_control_request(self) -> Mapping[str, str | UUID]:
        return self.command.to_control_request()
