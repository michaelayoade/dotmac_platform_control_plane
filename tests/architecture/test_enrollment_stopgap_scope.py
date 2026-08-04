"""The `LicenceDeliveryTarget` enrollment borrow stays confined to registration.

`docs/design/deployment-credentials.md` uses an active `LicenceDeliveryTarget`
as an eligibility INPUT to interim platform-admin enrollment policy. It is a
typo and scope guard — NOT proof a Deployment exists, since the same admin can
create the target and then the credential, so requiring one before the other
adds a step rather than an independent authority.

The authoritative Deployment entity belongs to `FleetDesiredStateService`,
which is not built. A stopgap that quietly becomes the authority is the drift
pattern this programme keeps hitting, so the borrow is bounded by construction:
ONE reader, on ONE path. A comment asking politely would not survive ordinary
refactoring; this fails the build.

When the fleet slice lands, this test and the reader it guards are deleted
together — retirement is not complete while any code path still reads a
delivery target for authorisation.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CREDENTIALS = REPO / "src" / "vendor_cp" / "licensing" / "credentials.py"

#: The single function permitted to read the delivery-target projection.
_PERMITTED_READER = "_authorised_enrollment_target"
_BORROWED = "LicenceDeliveryTarget"


def _functions_referencing(source: str, name: str) -> set[str]:
    """Every top-level function whose body mentions `name`."""
    tree = ast.parse(source)
    found: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == name:
                found.add(node.name)
            elif isinstance(sub, ast.Attribute) and sub.attr == name:
                found.add(node.name)
    return found


def test_only_the_registration_reader_touches_the_delivery_target() -> None:
    readers = _functions_referencing(CREDENTIALS.read_text(), _BORROWED)
    assert readers <= {_PERMITTED_READER}, (
        f"{_BORROWED} is a bounded enrollment stopgap, readable only by "
        f"{_PERMITTED_READER!r} during registration. These also read it: "
        f"{sorted(readers - {_PERMITTED_READER})}. A delivery target is not "
        "proof a Deployment exists — do not let the borrow spread. See "
        "docs/design/deployment-credentials.md, 'Enrollment authority'."
    )


def test_the_reader_exists_so_this_canary_cannot_pass_vacuously() -> None:
    """If the reader is renamed or deleted without updating this test, the
    assertion above would pass against an empty set and guard nothing."""
    readers = _functions_referencing(CREDENTIALS.read_text(), _BORROWED)
    assert readers == {_PERMITTED_READER}, (
        f"expected exactly {_PERMITTED_READER!r} to read {_BORROWED}, found "
        f"{sorted(readers)} — if the stopgap has been RETIRED, delete this "
        "module along with the reader rather than loosening it"
    )


def test_the_credential_lifecycle_is_not_coupled_to_target_status() -> None:
    """A target going inactive must NOT retire or revoke a credential. The
    target gated one moment — registration — and has no standing over an
    identity whose possession has since been proven; coupling them would let a
    delivery-routing edit revoke a proven deployment."""
    source = CREDENTIALS.read_text()
    lifecycle = _functions_referencing(source, "retired_at") | _functions_referencing(
        source, "revoked_at"
    )
    assert _PERMITTED_READER not in lifecycle, (
        "the enrollment reader also touches lifecycle timestamps — registration "
        "authorisation and credential lifecycle must stay separate"
    )
