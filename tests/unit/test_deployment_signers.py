"""Two purposes, two keys, and the refusals that keep them apart.

An observation signed by the authorization key cannot contradict the
authorization — which is the only reason the observation exists.

Every refusal here is asserted by CODE, never by prose. The first cut of this
suite matched on the message and found the bug it was written to find: three
tests refused the licensing pointer and passed while the by-value branch they
named had never run, because the namespace check answered first. `match=` was
the right instrument for finding that and the wrong one for pinning it — a
reworded sentence stops a prose assertion discriminating, silently.
"""

from __future__ import annotations

import dataclasses
import inspect
from dataclasses import dataclass

import pytest

from vendor_cp.deployment.signers import (
    AUTHORIZATION_PURPOSE,
    EXECUTION_OBSERVATION_PURPOSE,
    FORBIDDEN_SIGNING_POINTERS,
    POINTER_PREFIX,
    AuthorizationSignerPointer,
    ObservationSignerPointer,
    SignerPointerRefused,
    SignerRefusal,
    require_distinct_signers,
)

AUTH = "secret/dotmac/platform-cp/authorization-signing/primary"
OBS = "secret/dotmac/platform-cp/target-observation-signing/primary"

#: The refusal codes this file actually drives, maintained by hand beside the
#: tests that drive them. Ratcheted in both directions against the enum below,
#: so a fifth code cannot ship untested and a retired one cannot linger here.
EXERCISED_REFUSALS = frozenset(
    {
        SignerRefusal.FORBIDDEN_POINTER,
        SignerRefusal.FOREIGN_NAMESPACE,
        SignerRefusal.PURPOSE_MISMATCH,
        SignerRefusal.SHARED_POINTER,
        SignerRefusal.SHARED_KEY_MATERIAL,
        SignerRefusal.NOTHING_TO_COMPARE,
    }
)


def test_no_refusal_code_ships_without_a_test() -> None:
    """A vocabulary ratchet. A new `SignerRefusal` member fails here until it is
    added above, which is the moment to notice it has no test yet."""
    assert set(SignerRefusal) == EXERCISED_REFUSALS


def test_the_two_pointers_are_admitted() -> None:
    """SENSITIVITY. Every other test here is a refusal, and a validator only
    ever observed refusing might refuse everything."""
    assert AuthorizationSignerPointer(AUTH).purpose == AUTHORIZATION_PURPOSE
    assert ObservationSignerPointer(OBS).purpose == EXECUTION_OBSERVATION_PURPOSE


def test_every_forbidden_pointer_is_refused_by_value_whatever_its_namespace() -> None:
    """The property this module exists for, and the one that shipped dead.

    One key covering licence issuance and deployment permission means a party
    able to mint a licence can mint a deployment authorization. Asserting the
    CODE is what makes this test able to fail: a bare
    `pytest.raises(SignerPointerRefused)` passes just as happily when the
    namespace check answers first and the by-value comparison never runs.
    """
    assert FORBIDDEN_SIGNING_POINTERS, "an empty forbidden set refuses nothing"
    for pointer in FORBIDDEN_SIGNING_POINTERS:
        for factory in (AuthorizationSignerPointer, ObservationSignerPointer):
            with pytest.raises(SignerPointerRefused) as refused:
                factory(pointer)
            assert refused.value.refusal is SignerRefusal.FORBIDDEN_POINTER


def test_the_by_value_refusal_is_not_shadowed_by_the_namespace_check() -> None:
    """SENSITIVITY for the test above, and the whole reason it can bite.

    That test only proves the check order while some forbidden pointer is ALSO
    foreign. If every forbidden pointer moved under this product's own prefix,
    the namespace check could return in front of the by-value check again and
    nothing would notice — the guard would pass for the wrong reason a second
    time.
    """
    foreign_and_forbidden = {
        pointer
        for pointer in FORBIDDEN_SIGNING_POINTERS
        if not pointer.startswith(POINTER_PREFIX)
    }
    assert foreign_and_forbidden, (
        "no forbidden pointer is foreign, so nothing here proves the by-value "
        "check runs before the namespace check"
    )


@pytest.mark.parametrize(
    "foreign",
    (
        "secret/dotmac/vendor-control-plane/production/database",
        "secret/dotmac/other-product/authorization-signing/primary",
        "authorization-signing/primary",
    ),
)
def test_a_pointer_outside_this_products_space_is_refused(foreign: str) -> None:
    """A pointer elsewhere is another owner's key being borrowed.

    POSITIVE CONTROL for the ordering fix: the namespace refusal must still be
    reachable. These are deliberately pointers that are foreign and NOT
    forbidden — the licensing key belongs to the by-value test above, and
    asserting `FOREIGN_NAMESPACE` for it here is the exact confusion this suite
    now refuses to make.
    """
    with pytest.raises(SignerPointerRefused) as refused:
        AuthorizationSignerPointer(foreign)
    assert refused.value.refusal is SignerRefusal.FOREIGN_NAMESPACE


def test_a_signer_may_not_declare_the_other_purpose() -> None:
    """The purposes are not interchangeable, and swapping them is the exact
    mistake the separation exists to prevent."""
    with pytest.raises(SignerPointerRefused) as authorization:
        AuthorizationSignerPointer(AUTH, purpose=EXECUTION_OBSERVATION_PURPOSE)
    assert authorization.value.refusal is SignerRefusal.PURPOSE_MISMATCH
    with pytest.raises(SignerPointerRefused) as observation:
        ObservationSignerPointer(OBS, purpose=AUTHORIZATION_PURPOSE)
    assert observation.value.refusal is SignerRefusal.PURPOSE_MISMATCH


def test_one_pointer_cannot_serve_both_purposes() -> None:
    """The rule neither dataclass can see on its own. A pair naming one pointer
    twice satisfies every per-class refusal and still collapses the two
    questions into one key."""
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH), ObservationSignerPointer(OBS)
    )
    same = "secret/dotmac/platform-cp/shared/primary"
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(
            AuthorizationSignerPointer(same), ObservationSignerPointer(same)
        )
    assert refused.value.refusal is SignerRefusal.SHARED_POINTER


#: Class-level attributes these descriptors may carry beyond their two fields.
#: Declared, so adding one is a reviewed change rather than a silent widening of
#: what the seam can hold.
DECLARED_CLASS_ATTRIBUTES = frozenset({"material"})


def test_no_key_material_can_be_held_here() -> None:
    """The seam carries pointers. A field able to hold a secret would make this
    module a place where one could come to rest.

    ## The trap, because it is not obvious and you will meet it

    `__dataclass_fields__` is NOT the set of instance fields. It also carries
    ClassVar and InitVar **pseudo-fields**, so a class constant appears in it
    exactly as a real field does. Declaring `material: ClassVar[MaterialKind]`
    therefore read as a new place material could rest, and the original
    one-line assertion had no way to tell a constant from state.
    `dataclasses.fields()` is the set that answers the question this test asks.

    ## Why ClassVar is fine here and InitVar would not be

    This is the distinction that matters, and it is not a technicality.

    A **ClassVar** is one value on the class. It is not per-instance state and
    it **cannot be passed to the constructor**, so no caller can hand material
    to a descriptor through it. It is a declaration a reader consults --
    `material` says whether the pointer names private signing material or a
    public verification identity -- and declarations are what this module is
    made of.

    An **InitVar is an `__init__` parameter.** That is precisely a way material
    could be handed IN, at construction, by any caller -- which is the thing
    this test exists to refuse. The two look identical in
    `__dataclass_fields__` and are opposites for this purpose, which is why
    claim 3 below separates them by asking the constructor rather than by
    trusting the annotation.

    ## If you are adding one

    A new ClassVar: add its name to `DECLARED_CLASS_ATTRIBUTES` and it passes.
    That list exists so widening what the seam carries is a reviewed change
    rather than a silent one.

    A new InitVar: don't. If a descriptor genuinely needs a value at
    construction it belongs as a normal field and this test should be argued
    with on the merits, not amended around.
    """
    for pointer in (AuthorizationSignerPointer(AUTH), ObservationSignerPointer(OBS)):
        cls = type(pointer)

        # 1. INSTANCE state is exactly the two pointers-only fields. This is the
        #    original claim, now made against the set that actually answers it.
        instance_fields = {field.name for field in dataclasses.fields(cls)}
        assert instance_fields == {"pointer", "purpose"}, cls.__name__

        # 2. Everything else on the dataclass is declared. A pseudo-field added
        #    later fails here instead of arriving unnoticed.
        extras = set(cls.__dataclass_fields__) - instance_fields
        assert (
            extras <= DECLARED_CLASS_ATTRIBUTES
        ), f"{cls.__name__} carries undeclared dataclass entries {sorted(extras)}"

        # 3. And each extra is a ClassVar, not an InitVar. The distinction is
        #    the whole point: an InitVar IS an `__init__` parameter, so it is a
        #    way material could be handed IN, which is exactly what this test
        #    exists to refuse. A ClassVar cannot be passed to the constructor.
        accepted = set(inspect.signature(cls).parameters)
        assert not (extras & accepted), (
            f"{cls.__name__} accepts {sorted(extras & accepted)} at construction; "
            "an InitVar can carry material in, which a ClassVar cannot"
        )


def test_signer_purposes_match_the_installed_control() -> None:
    """Restated constants must not drift from the authority that enforces them.

    Compared against the installed distribution rather than a changelog. Skipped
    only where Control predates the purpose split — and the skip says which
    version it saw, so a silent pass is not mistaken for agreement.
    """
    import importlib.metadata as metadata

    try:
        installed = metadata.version("dotmac-deployment-control")
    except metadata.PackageNotFoundError:  # pragma: no cover - hard dependency
        installed = "absent"
    reason = (
        f"installed dotmac-deployment-control {installed} predates the purpose "
        "split; these constants are compared once it is pinned"
    )
    control_authorization = pytest.importorskip(
        "dotmac_deployment_control.authorization", reason=reason
    )
    control_observation = pytest.importorskip(
        "dotmac_deployment_control.execution_observation", reason=reason
    )
    assert AUTHORIZATION_PURPOSE == control_authorization.AUTHORIZATION_PURPOSE
    assert (
        EXECUTION_OBSERVATION_PURPOSE
        == control_observation.EXECUTION_OBSERVATION_PURPOSE
    )


# ── distinctness is a property of the SET, not of a pair ────────────────────


@dataclass(frozen=True, slots=True)
class _Signer:
    """A purpose-bound pointer whose class this module does not ship yet.

    `deployment_dispatch` has no descriptor anywhere and `deployment_recovery`
    is Control's, so distinctness must be checkable for them before their
    classes land -- otherwise the guard arrives after the ceremony it exists to
    protect. `platform_release_evidence` was in this list until it gained
    `ReleaseEvidenceSignerPointer`; each purpose that gains a type leaves it.
    Structural typing is what makes that possible.
    """

    pointer: str
    purpose: str


DISPATCH = _Signer(f"{POINTER_PREFIX}dispatch-signing/primary", "deployment_dispatch")
EVIDENCE = _Signer(
    f"{POINTER_PREFIX}release-evidence-signing/primary", "platform_release_evidence"
)


def test_four_distinct_signers_are_admitted() -> None:
    """POSITIVE CONTROL for the widened check."""
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH),
        ObservationSignerPointer(OBS),
        DISPATCH,
        EVIDENCE,
    )


def test_three_purposes_sharing_one_pointer_are_all_named() -> None:
    """A pair-shaped check saw one sixth of this question at four identities."""
    shared = f"{POINTER_PREFIX}shared/primary"
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(
            AuthorizationSignerPointer(shared),
            ObservationSignerPointer(shared),
            _Signer(shared, "deployment_dispatch"),
            EVIDENCE,
        )
    assert refused.value.refusal is SignerRefusal.SHARED_POINTER
    message = str(refused.value)
    for purpose in ("deployment_authorization", "deployment_dispatch"):
        assert purpose in message


def test_two_disjoint_pairs_are_both_reported() -> None:
    """An operator repairing one collision per run re-runs the ceremony once per
    pair, which is the operator-surface defect in its ceremony form."""
    first = f"{POINTER_PREFIX}one/primary"
    second = f"{POINTER_PREFIX}two/primary"
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(
            AuthorizationSignerPointer(first),
            _Signer(first, "deployment_dispatch"),
            ObservationSignerPointer(second),
            _Signer(second, "platform_release_evidence"),
        )
    message = str(refused.value)
    assert first in message
    assert second in message


def test_two_pointers_holding_one_key_are_refused_when_fingerprints_are_given() -> None:
    """A pointer is a spelling; the key is the thing.

    Distinct pointers pass every pointer comparison and still collapse two
    purposes into one key. Fingerprints are PUBLIC, so comparing them holds this
    module to pointers-only while still catching the collision.
    """
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(
            AuthorizationSignerPointer(AUTH),
            ObservationSignerPointer(OBS),
            fingerprints={AUTH: "fp-same", OBS: "fp-same"},
        )
    assert refused.value.refusal is SignerRefusal.SHARED_KEY_MATERIAL


def test_distinct_keys_at_distinct_pointers_are_admitted() -> None:
    """SENSITIVITY for the fingerprint check: it must not refuse everything."""
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH),
        ObservationSignerPointer(OBS),
        fingerprints={AUTH: "fp-a", OBS: "fp-b"},
    )


def test_without_fingerprints_the_shared_key_shape_is_not_checked_here() -> None:
    """The boundary, asserted so neither side assumes the other has it.

    Omitting `fingerprints` is choosing the weaker check. This module may not
    fetch them -- that would be dereferencing a pointer -- so the shape is
    unmonitored HERE and belongs to Control's own
    `dispatch_signer_purpose_reused`, which sees one ordered pair at signing
    time. Asserting the gap keeps it from being quietly assumed closed.
    """
    require_distinct_signers(
        AuthorizationSignerPointer(AUTH), ObservationSignerPointer(OBS)
    )


def test_fewer_than_two_signers_cannot_pass_for_a_check() -> None:
    """A call that can only ever pass is not a check."""
    with pytest.raises(SignerPointerRefused) as refused:
        require_distinct_signers(AuthorizationSignerPointer(AUTH))
    assert refused.value.refusal is SignerRefusal.NOTHING_TO_COMPARE
