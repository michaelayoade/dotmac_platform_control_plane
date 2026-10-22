"""Startup composition for the opt-in configured deploy signer."""

import os

from sqlalchemy.orm import Session

from .candidates import GitHubCandidateEvidenceReader
from .contracts import ContractError, require
from .gate_admission import load_scope
from .keys import ConfiguredDesiredSigner
from .ledger import GitLedger
from .projection import rebuild
from .service import DeployAgentService

_runtime: DeployAgentService | None = None


def install_runtime() -> None:
    global _runtime
    enabled = os.environ.get("VENDOR_DEPLOY_AGENT_ENABLED", "false")
    require(enabled in {"true", "false"}, "invalid_configuration")
    _runtime = None
    if enabled == "true":
        signer = ConfiguredDesiredSigner(
            os.environ.get("VENDOR_DESIRED_SIGNING_KEY_ID", ""),
            os.environ.get("VENDOR_DESIRED_SIGNING_KEY_FILE", ""),
            os.environ.get("VENDOR_DESIRED_SIGNING_KEY_POINTER", ""),
        )
        ledger = GitLedger(os.environ.get("VENDOR_DEPLOY_LEDGER_DIR", ""))
        with ledger.transaction():
            pass
        reader = GitHubCandidateEvidenceReader(
            os.environ.get("VENDOR_DEPLOY_GH_EXECUTABLE", ""),
            os.environ.get("VENDOR_DEPLOY_GH_SHA256", ""),
        )
        scope_file = os.environ.get("VENDOR_DEPLOY_GATE_SCOPE_FILE", "")
        scope = load_scope(scope_file) if scope_file else None
        _runtime = DeployAgentService(
            ledger, signer, candidate_reader=reader, gate_scope=scope
        )


def service() -> DeployAgentService:
    if _runtime is None:
        raise ContractError("feature_disabled")
    return _runtime


def ledger_rebuild(db: Session) -> dict[str, int | bool]:
    owner = service()
    with owner.ledger.transaction():
        owner.validate_history()
        return rebuild(db, owner.ledger)
