"""A typed digest, because a digest compared as a string is compared wrongly.

`dotmac-deployment-control` stores a plan digest as **bare hex**. This facility
emits the **`sha256:`-prefixed** form. `approve_plan` compares the two with a
raw ``!=``. Unnormalized, two spellings of one value are unequal, and the
failure surfaces as an authorization refusal — an alarm that reads as
"something is wrong with the approval" when the truth is "something is wrong
with the formatting". That alarm gets suppressed, and suppressing it removes a
real control.

`provenance.normalize_digest` patched the specific case. This module generalises
it into a TYPE, because the string form keeps coming back:

    Digest.parse("sha256:ab…")   # prefixed
    Digest.parse("AB…")          # bare, uppercase
    Digest.parse(…) == Digest.parse(…)   # value equality, spelling-independent
    str(digest)                  # always `sha256:<64 lowercase hex>`

## Why a type rather than a normalize function

A function has to be CALLED. Every new comparison site is a new chance to
forget, and forgetting produces a false refusal rather than a crash — the
failure mode that survives review. A value object cannot be compared wrongly:
`Digest.__eq__` is over the algorithm and the raw bytes, so two spellings of one
digest are one value and there is no string left to get wrong.

## What is refused, and why each one

- **an unknown algorithm** — `md5:…` is not a weaker digest here, it is a
  different namespace, and silently accepting it would let two unrelated values
  compare equal by length.
- **the wrong length** — a truncated digest is the classic way a comparison
  passes on a prefix.
- **uppercase drift** — accepted on INPUT and normalized, refused on OUTPUT.
  Hex is case-insensitive as a number and case-sensitive as a string, which is
  exactly the mismatch that makes string comparison unsafe; the canonical form
  is lowercase so a stored digest has one spelling.
- **a bare value where the algorithm is unknown** — accepted only because
  Control persists that shape today. It is a COMPATIBILITY affordance and is
  named as one, not a second canonical form.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

from .errors import SpecError

__all__ = [
    "ALGORITHMS",
    "CANONICAL_ALGORITHM",
    "Digest",
    "require_same_digest",
]

#: The only algorithm this facility produces. A tuple rather than a bare
#: constant so adding one is a declaration rather than an edit to a comparison.
ALGORITHMS: Final[dict[str, int]] = {"sha256": 32}

CANONICAL_ALGORITHM: Final = "sha256"

_HEX = re.compile(r"^[0-9a-f]+$")


@dataclass(frozen=True, slots=True, order=False)
class Digest:
    """One content digest: an algorithm and its raw bytes.

    Equality and hashing are over both fields, so a `sha256` and a
    hypothetical future `sha512` of the same content are never equal — which is
    correct, and is the thing a hex-string comparison cannot express.
    """

    algorithm: str
    raw: bytes

    def __post_init__(self) -> None:
        expected = ALGORITHMS.get(self.algorithm)
        if expected is None:
            raise SpecError(
                f"unknown digest algorithm {self.algorithm!r}; this facility "
                f"understands {sorted(ALGORITHMS)}. An unrecognised algorithm is "
                "a different namespace, not a weaker digest"
            )
        if len(self.raw) != expected:
            raise SpecError(
                f"a {self.algorithm} digest is {expected} bytes, got "
                f"{len(self.raw)}. A truncated digest is how a comparison comes "
                "to pass on a prefix"
            )

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def parse(cls, value: str, *, where: str = "digest") -> Digest:
        """Accept either spelling; produce one value.

        The bare form has no algorithm in it, so it can only mean the canonical
        one. That is an assumption, and it is admissible for exactly one reason:
        `dotmac-deployment-control` persists `plan_digest` as bare hex in a
        `String(64)` column, so the algorithm is structurally pinned by the
        schema. It is not a licence for new callers to emit bare digests.
        """
        if not isinstance(value, str):
            raise SpecError(f"{where}: a digest must be a string, got {type(value)}")
        text = value.strip()
        if not text:
            raise SpecError(f"{where}: a digest is required, and this one is empty")
        algorithm, separator, body = text.partition(":")
        if not separator:
            algorithm, body = CANONICAL_ALGORITHM, text
        algorithm = algorithm.lower()
        body = body.lower()
        if algorithm not in ALGORITHMS:
            raise SpecError(
                f"{where}: unknown digest algorithm {algorithm!r} in {value!r}; "
                f"expected one of {sorted(ALGORITHMS)}"
            )
        if not _HEX.match(body):
            raise SpecError(
                f"{where}: {value!r} is not hexadecimal. A digest that cannot be "
                "decoded cannot be compared, and must not be treated as opaque"
            )
        if len(body) != ALGORITHMS[algorithm] * 2:
            raise SpecError(
                f"{where}: a {algorithm} digest is "
                f"{ALGORITHMS[algorithm] * 2} hex characters, got {len(body)} "
                f"in {value!r}"
            )
        return cls(algorithm=algorithm, raw=bytes.fromhex(body))

    @classmethod
    def of(cls, payload: bytes) -> Digest:
        """The canonical digest OF some bytes — one place that knows which
        algorithm this facility uses."""
        return cls(algorithm=CANONICAL_ALGORITHM, raw=hashlib.sha256(payload).digest())

    # ── serialization ───────────────────────────────────────────────────────

    @property
    def hex(self) -> str:
        """Lowercase hex with no prefix — the shape Control's column holds."""
        return self.raw.hex()

    def __str__(self) -> str:
        """The canonical form. One spelling, always."""
        return f"{self.algorithm}:{self.raw.hex()}"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Digest({self})"


def require_same_digest(terms: dict[str, str], *, what: str) -> Digest:
    """Every named term must be the same digest, or refuse naming the odd ones.

    Takes a MAPPING rather than a sequence so a refusal can say WHICH term
    disagreed. A message that reports two digests without saying whose they are
    sends the reader to the wrong system.

    Two terms cannot satisfy a three-term gate: the caller decides how many
    terms there are, and this refuses an empty or single-term call outright so
    a gate cannot be weakened by quietly passing fewer terms than it names.
    """
    if len(terms) < 2:
        raise SpecError(
            f"{what}: a digest-equality check needs at least two named terms, "
            f"got {sorted(terms)}. A check over one term always passes and "
            "proves nothing"
        )
    parsed = {
        name: Digest.parse(value, where=f"{what}.{name}")
        for name, value in sorted(terms.items())
    }
    distinct = {str(digest) for digest in parsed.values()}
    if len(distinct) != 1:
        detail = ", ".join(f"{name}={digest}" for name, digest in parsed.items())
        raise SpecError(
            f"{what}: the terms do not agree ({detail}). Every term must be the "
            "same digest — if they differ, the thing that ran is not the thing "
            "that was authorized"
        )
    return next(iter(parsed.values()))
