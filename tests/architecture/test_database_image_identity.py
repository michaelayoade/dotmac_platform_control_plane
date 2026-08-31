"""The database image is one exact artifact, named the same way in both places.

`postgres:16` is a MUTABLE tag. Two services resolving it on different days run
different bytes while the file says they are identical, and nothing in the
deployment notices — the compose file, the descriptor and the running container
all keep agreeing with each other about a name that has silently changed
underneath them.

The distinction this file holds:

* the MAJOR VERSION is a compatibility DECLARATION — "this product's schema and
  its restore procedure target PostgreSQL 16";
* the DIGEST is artifact IDENTITY — "these exact bytes".

Both are kept, and they are not interchangeable. A digest alone loses the
declaration a reader needs to reason about upgrades; a major alone loses the
identity a recovery has to reproduce.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.production.yml"

#: `postgres:<major>@sha256:<64 hex>` and nothing looser.
PINNED = re.compile(r"postgres:(?P<major>\d+)@sha256:(?P<digest>[0-9a-f]{64})\b")
#: A bare tag with no digest — the shape being removed.
MUTABLE = re.compile(r"postgres:\d+(?![.\w]*@sha256:)")

DECLARED_MAJOR = 16


def _image_lines() -> list[str]:
    return [
        line.strip()
        for line in COMPOSE.read_text().splitlines()
        if line.strip().startswith("image:") and "POSTGRES_IMAGE" in line
    ]


def test_both_database_services_declare_an_image() -> None:
    """`db` and `manifest-init` both run Postgres; a check covering one of them
    leaves the other free to drift."""
    assert len(_image_lines()) == 2, _image_lines()


def test_every_database_image_is_pinned_by_digest() -> None:
    for line in _image_lines():
        assert PINNED.search(line), f"not digest-pinned: {line}"


def test_both_services_use_the_SAME_digest() -> None:
    """One artifact, not two that happen to be pinned.

    Two different digests would still satisfy "everything is pinned" while
    running two different databases against one schema and one restore
    procedure.
    """
    digests = {
        m.group("digest") for line in _image_lines() for m in [PINNED.search(line)] if m
    }
    assert len(digests) == 1, f"expected one digest, found {sorted(digests)}"


def test_the_major_version_survives_as_a_declaration() -> None:
    """The digest is identity; the major is the compatibility statement, and
    the descriptor's `postgres_major` has to agree with it."""
    majors = {
        int(m.group("major"))
        for line in _image_lines()
        for m in [PINNED.search(line)]
        if m
    }
    assert majors == {DECLARED_MAJOR}, majors

    descriptor = (ROOT / "deploy" / "product.toml").read_text()
    assert f"postgres_major = {DECLARED_MAJOR}" in descriptor


def test_no_mutable_database_tag_remains() -> None:
    for line in _image_lines():
        assert not MUTABLE.search(line), f"mutable tag: {line}"


def test_the_checks_refuse_a_planted_mutable_or_second_image() -> None:
    """BOTH HALVES, on each rule, because every assertion above is a negative
    that an empty or malformed file would also satisfy."""
    good = "image: ${VENDOR_POSTGRES_IMAGE:-postgres:16@sha256:" + "a" * 64 + "}"
    other = "image: ${VENDOR_POSTGRES_IMAGE:-postgres:16@sha256:" + "b" * 64 + "}"
    mutable = "image: ${VENDOR_POSTGRES_IMAGE:-postgres:16}"

    # admitted
    assert PINNED.search(good) and not MUTABLE.search(good)
    # a mutable tag is refused
    assert MUTABLE.search(mutable) and not PINNED.search(mutable)
    # a SECOND, different digest is refused by the sameness rule
    digests = {
        m.group("digest") for line in (good, other) for m in [PINNED.search(line)] if m
    }
    assert len(digests) == 2, "the sameness rule would not have noticed two images"
