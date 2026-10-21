"""Local bare-remote proof of held authority and manual non-force recovery."""

import fcntl
import subprocess

import pytest
from test_service import activate, issue
from test_service import owner as shared_owner

from vendor_cp.deploy_agent import contracts as c

owner = shared_owner


def git(directory, *args):
    return subprocess.run(  # noqa: S603 - fixed local Git fixture executable
        ["/usr/bin/git", "-C", str(directory), *args],
        check=True,
        capture_output=True,
    ).stdout


@pytest.fixture
def remote_owner(owner, tmp_path_factory):
    service, projection = owner
    activate(owner)
    remote = tmp_path_factory.mktemp("ledger-remote")
    git(remote, "init", "--bare", "-b", "main")
    service.ledger.git("remote", "add", "origin", str(remote))
    service.ledger.git("push", "--set-upstream", "origin", "main")
    service.ledger.remote = "origin"
    return owner, remote


def recover_while_cp_stopped(service):
    """Fixture execution of documented owner procedure, not a production CLI."""
    ledger = service.ledger
    with (ledger.root / ".git" / "deploy-agent.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger.git("fetch", "origin")
        local = ledger.git("rev-parse", "HEAD")
        remote = ledger.git("rev-parse", "origin/main")
        ledger.git(
            "merge-base",
            "--is-ancestor",
            remote.decode().strip(),
            local.decode().strip(),
        )
        service.validate_history()
        ledger.git("push", "origin", "HEAD")
        ledger.git("fetch", "origin")
        assert ledger.git("rev-parse", "HEAD") == ledger.git("rev-parse", "origin/main")


def test_rejected_push_holds_local_authority_until_validated_nonforce_recovery(
    remote_owner,
):
    owner, remote = remote_owner
    service, projection = owner
    before = list(projection)
    remote_before = git(remote, "rev-parse", "HEAD")
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o700)
    with pytest.raises(c.ContractError, match="ledger_unavailable"):
        issue(owner)
    local_commit = service.ledger.git("rev-parse", "HEAD")
    assert local_commit != remote_before == git(remote, "rev-parse", "HEAD")
    assert projection == before
    service.validate_history()
    assert service.ledger.records("desired/")
    assert not git(remote, "ls-tree", "-r", "--name-only", "HEAD", "desired")
    for attempt in (
        lambda: service.latest("dotmac_sub", "staging", "dotmac-sub-staging"),
        lambda: issue(owner),
    ):
        with pytest.raises(c.ContractError, match="ledger_conflict"):
            attempt()
    hook.unlink()
    recover_while_cp_stopped(service)
    _, envelope, _ = issue(owner)
    assert (
        service.ledger.git("rev-parse", "HEAD")
        == local_commit
        == git(remote, "rev-parse", "HEAD")
    )
    assert service.latest("dotmac_sub", "staging", "dotmac-sub-staging") == envelope
    assert any(path.startswith("desired/") for path, _ in projection)


def test_ambiguous_accepted_push_never_serves_before_remote_confirmation(
    remote_owner, monkeypatch
):
    owner, remote = remote_owner
    service, projection = owner
    before = list(projection)
    original = service.ledger.git

    def lost_ack(*args):
        result = original(*args)
        if args[0] == "push":
            raise c.ContractError("ledger_unavailable")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(service.ledger, "git", lost_ack)
        with pytest.raises(c.ContractError, match="ledger_unavailable"):
            issue(owner)
    accepted_commit = git(remote, "rev-parse", "HEAD")
    assert service.ledger.git("rev-parse", "HEAD") == accepted_commit
    assert projection == before

    def unavailable_confirmation(*args):
        if args[0] == "fetch":
            raise c.ContractError("ledger_unavailable")
        return original(*args)

    with monkeypatch.context() as patch:
        patch.setattr(service.ledger, "git", unavailable_confirmation)
        with pytest.raises(c.ContractError, match="ledger_unavailable"):
            service.latest("dotmac_sub", "staging", "dotmac-sub-staging")
    recover_while_cp_stopped(service)
    _, envelope, _ = issue(owner)
    assert service.ledger.git("rev-parse", "HEAD") == accepted_commit
    assert service.latest("dotmac_sub", "staging", "dotmac-sub-staging") == envelope
    assert any(path.startswith("desired/") for path, _ in projection)


def test_divergent_remote_requires_hold_and_preserves_both_histories(
    remote_owner, tmp_path_factory
):
    owner, remote = remote_owner
    service, projection = owner
    before = list(projection)
    hook = remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o700)
    with pytest.raises(c.ContractError, match="ledger_unavailable"):
        issue(owner)
    local_commit = service.ledger.git("rev-parse", "HEAD")
    hook.unlink()
    other = tmp_path_factory.mktemp("other-ledger-writer")
    git(other, "clone", str(remote), ".")
    git(other, "config", "user.name", "Unrecognised fixture writer")
    git(other, "config", "user.email", "fixture@example.invalid")
    (other / "unknown.txt").write_text("retained unknown remote data\n")
    git(other, "add", "unknown.txt")
    git(other, "commit", "-m", "independent remote advancement")
    git(other, "push", "origin", "HEAD")
    remote_commit = git(remote, "rev-parse", "HEAD")
    with pytest.raises(c.ContractError, match="ledger_unavailable"):
        recover_while_cp_stopped(service)
    assert service.ledger.git("rev-parse", "HEAD") == local_commit
    assert git(remote, "rev-parse", "HEAD") == remote_commit != local_commit
    assert git(remote, "show", "HEAD:unknown.txt") == b"retained unknown remote data\n"
    assert service.ledger.records("desired/") and projection == before
    with pytest.raises(c.ContractError, match="ledger_conflict"):
        service.latest("dotmac_sub", "staging", "dotmac-sub-staging")
