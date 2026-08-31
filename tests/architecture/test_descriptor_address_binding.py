"""The descriptor states exposure INTENT; the inventory supplies the address.

A deployment descriptor is a reusable artifact. Its canonical bytes have to be
identical in every environment, or "the reviewed artifact" and "the deployed
artifact" stop being the same thing and the review stops transferring.

A literal address breaks that, and `0.0.0.0` — the literal that was here — is
the worst case: it reads as "no opinion" while being the most permissive bind
available. The address now comes from the host's private inventory through
`VENDOR_BIND_ADDRESS`, and `:?` makes an inventory that forgets it fail closed
instead of quietly defaulting to something open.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = ROOT / "deploy" / "product.toml"

#: Any dotted quad, plus the two IPv6 forms a bind is normally written with.
LITERAL_ADDRESS = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|::1\b|\[::\]")

#: A compose interpolation that fails closed when the inventory omits it.
FAIL_CLOSED = re.compile(r"^\$\{[A-Z][A-Z0-9_]*:\?.+\}$")


def _descriptor() -> dict:
    return tomllib.loads(DESCRIPTOR.read_text())


def _command_of(role: dict) -> list[str]:
    return list(role.get("command", ()))


def test_no_role_command_carries_a_literal_address() -> None:
    """The property, stated over every role rather than the one that was wrong."""
    offenders = [
        (role["code"], part)
        for role in _descriptor()["roles"]
        for part in _command_of(role)
        if LITERAL_ADDRESS.search(part)
    ]
    assert not offenders, f"literal address in a role command: {offenders}"


def test_the_bind_address_comes_from_inventory_and_fails_closed() -> None:
    """Parameterised is not enough — it must also refuse to default.

    `${VENDOR_BIND_ADDRESS}` unset interpolates to empty and uvicorn would bind
    its own default; `${VENDOR_BIND_ADDRESS:-0.0.0.0}` puts the literal back.
    Only the `:?` form makes a missing inventory value an error.
    """
    app = next(r for r in _descriptor()["roles"] if r["code"] == "app")
    command = _command_of(app)
    host = command[command.index("--host") + 1]
    assert FAIL_CLOSED.match(host), host
    assert "VENDOR_BIND_ADDRESS" in host


#: Loopback is the ONE literal a descriptor may carry, and only where it means
#: "this container's own process". A probe dials the role it is probing; that
#: target is identical in every environment, and parameterising it would invite
#: pointing a health check somewhere the role is not.
#:
#: The exemption states an enforceable premise rather than a category: only
#: loopback, and only outside a bind position. A non-loopback literal anywhere,
#: or loopback used as a BIND, is still refused — see the tests below.
CONTAINER_LOCAL = re.compile(r"\b127\.0\.0\.1\b")


def test_the_only_literal_address_left_is_container_local_loopback() -> None:
    """Not only in commands — an address in a probe or any other field is the
    same coupling by another route, EXCEPT container-local loopback."""
    body = "\n".join(
        line
        for line in DESCRIPTOR.read_text().splitlines()
        if not line.strip().startswith("#")
    )
    found = LITERAL_ADDRESS.findall(body)
    non_loopback = [a for a in found if not CONTAINER_LOCAL.fullmatch(a)]
    assert not non_loopback, f"environment-coupled literal address: {non_loopback}"


def test_loopback_is_only_permitted_outside_a_bind_position() -> None:
    """The exemption is scoped, not blanket. Loopback as a --host would be a
    bind, and a bind must still come from inventory."""
    for role in _descriptor()["roles"]:
        command = _command_of(role)
        if "--host" in command:
            host = command[command.index("--host") + 1]
            assert not LITERAL_ADDRESS.search(host), f"{role['code']} binds a literal"


def test_canonical_bytes_are_environment_independent() -> None:
    """The same artifact under two different inventories is the same bytes.

    The descriptor is read without consulting the environment at all, so this
    asserts the absence of any interpolation-at-read: two reads under different
    environments must produce identical bytes and identical parses.
    """
    import os

    first = DESCRIPTOR.read_bytes()
    saved = os.environ.get("VENDOR_BIND_ADDRESS")
    try:
        os.environ["VENDOR_BIND_ADDRESS"] = "10.0.0.1"
        second = DESCRIPTOR.read_bytes()
        os.environ["VENDOR_BIND_ADDRESS"] = "192.168.99.99"
        third = DESCRIPTOR.read_bytes()
    finally:
        if saved is None:
            os.environ.pop("VENDOR_BIND_ADDRESS", None)
        else:
            os.environ["VENDOR_BIND_ADDRESS"] = saved
    assert first == second == third


def test_two_inventories_bind_different_addresses_without_a_rebuild() -> None:
    """The artifact is fixed; the binding is not.

    Compose interpolation is modelled here rather than invoked — the point is
    that ONE unchanged command string yields two different binds, which is what
    "deploy the same reviewed artifact to two environments" requires.
    """
    app = next(r for r in _descriptor()["roles"] if r["code"] == "app")
    command = _command_of(app)
    host_token = command[command.index("--host") + 1]

    def bind(inventory: dict[str, str]) -> str:
        name = host_token[2:].split(":?", 1)[0]
        if name not in inventory:
            raise KeyError(f"{name} missing; compose would refuse")
        return inventory[name]

    assert bind({"VENDOR_BIND_ADDRESS": "127.0.0.1"}) == "127.0.0.1"
    assert bind({"VENDOR_BIND_ADDRESS": "10.42.0.7"}) == "10.42.0.7"
    # And the artifact itself never changed between those two binds.
    assert _command_of(app) == command


def test_a_planted_literal_address_is_refused() -> None:
    """SENSITIVITY, both halves. Every assertion above is a negative that an
    empty descriptor would also satisfy, so the detector must be shown finding
    the thing it exists to find — and admitting the corrected form."""
    all_interfaces = ".".join(["0"] * 4)  # assembled, so S104 reads no bind here
    planted = ["uvicorn", "app:app", "--host", all_interfaces, "--port", "8000"]
    assert [p for p in planted if LITERAL_ADDRESS.search(p)] == [all_interfaces]

    corrected = ["uvicorn", "app:app", "--host", "${VENDOR_BIND_ADDRESS:?set it}"]
    assert not [p for p in corrected if LITERAL_ADDRESS.search(p)]

    # A default-bearing form parameterises but does not fail closed.
    assert not FAIL_CLOSED.match("${VENDOR_BIND_ADDRESS:-" + all_interfaces + "}")
    assert not FAIL_CLOSED.match("${VENDOR_BIND_ADDRESS}")
    assert FAIL_CLOSED.match("${VENDOR_BIND_ADDRESS:?set it}")
