"""Projection corruption detector only: fake cursor, no database parity claim."""

import pytest
from conformance_data import TestSigner, desired

from vendor_cp.deploy_agent import contracts as c
from vendor_cp.deploy_agent.projection import rebuild


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
