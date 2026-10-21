"""Projection corruption detector only: fake cursor, no database parity claim."""

from unittest.mock import Mock
from uuid import uuid4

import pytest
from conformance_data import TestSigner, desired
from fastapi import HTTPException, Response

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent.projection import rebuild
from vendor_cp.deploy_agent.router import receipt
from vendor_cp.deploy_agent.service import DeployAgentService


@pytest.mark.parametrize("corruption", ["envelope", "nonce", "kind", "deployment_ref"])
def test_projection_refuses_corruption_with_preserved_fingerprint(corruption):
    envelope = c.seal(c.DESIRED, desired(), TestSigner())
    path = "desired/dotmac_sub/staging/dotmac-sub-staging/fixture.json"
    row = [
        path,
        "desired",
        desired()["deployment_ref"],
        None,
        None,
        c.digest(envelope),
        envelope,
    ]
    if corruption == "envelope":
        row[-1] = {**envelope, "signature_b64": "corrupted"}
    elif corruption == "nonce":
        row[4] = "corrupted"
    elif corruption == "kind":
        row[1] = "applied"
    else:
        row[2] = "foreign/staging/host"

    class CursorOnly:
        def execute(self, _statement):
            return [row]

        def commit(self):
            pytest.fail("corruption must refuse before commit")

    class FixtureLedger:
        def events(self):
            return [(path, envelope)]

    with pytest.raises(c.ContractError, match="projection_conflict"):
        rebuild(CursorOnly(), FixtureLedger())


@pytest.mark.parametrize("missing", [False, True])
def test_receipt_reads_stored_evidence_only_in_fixed_scope(monkeypatch, missing):
    report, ref, db = uuid4(), "fixed/staging/host", Mock()
    row = dict(
        deployment_ref=ref, report_id=str(report), path="stored", fingerprint="stored"
    )
    db.execute.return_value.mappings.return_value.one_or_none.return_value = (
        None if missing else row
    )
    owner = DeployAgentService(None, None, deployment_ref=ref)
    monkeypatch.setattr("vendor_cp.deploy_agent.router.service", lambda: owner)
    response = Response()
    if missing:
        with pytest.raises(HTTPException) as error:
            receipt(report, None, db, response)
        assert error.value.status_code == 404
    else:
        assert receipt(report, None, db, response) == row
    statement, params = db.execute.call_args.args
    assert "WHERE kind='applied' AND deployment_ref=:ref AND report_id=:report" in str(
        statement
    )
    assert params == {"ref": ref, "report": str(report)}
    assert len(db.mock_calls) == 3
    assert response.headers["Cache-Control"] == "no-store"
