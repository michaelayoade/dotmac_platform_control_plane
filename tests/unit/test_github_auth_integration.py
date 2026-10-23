"""Installed CLI transport over the single host credential owner, with fakes."""

import pytest

from vendor_cp import github_app_credentials as owner
from vendor_cp.cli import build_parser
from vendor_cp.cli.exits import Refusal


def test_installed_cli_dispatch_returns_public_owner_receipt(monkeypatch):
    receipt = {"app_id": 5448762, "installation_id": 174650996}
    calls = []

    def renew():
        calls.append(True)
        return receipt

    monkeypatch.setattr(owner, "renew_host_credentials", renew)
    args = build_parser().parse_args(["admin", "github-auth-renew"])
    result = args.handler(args)
    assert calls == [True]
    assert result.command == "admin github-auth-renew" and result.data == receipt


def test_installed_cli_carries_safe_owner_failure(monkeypatch):
    def renew():
        raise owner.GitHubCredentialError("credential renewal refused")

    monkeypatch.setattr(owner, "renew_host_credentials", renew)
    args = build_parser().parse_args(["admin", "github-auth-renew"])
    with pytest.raises(Refusal, match="credential renewal refused") as error:
        args.handler(args)
    assert error.value.code == "execution.failed"
