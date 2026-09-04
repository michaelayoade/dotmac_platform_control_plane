"""The mint dossier's FENCED BLOCKS, checked against its own custody table.

A document like this has two registers. The tables are what a reader reads; the
fenced blocks are what an operator pastes. They can disagree, and when they do
the summary is what gets believed while the steps are what get run.

`test_signing_identity_dossier.py` binds the first register: it derives the
purpose/pointer pairs from the identity table and constructs the real
descriptors with them. That guard is good and it was blind to exactly this,
because a well-formed table says nothing about whether the steps implement it.

The document merged as #134/#142 proved the point. Its table said the
target-observation private half lives on the target — correct — while four of
its own steps generated that key on the workstation, wrote `private_key_pem`
into this product's namespace, granted a Platform CP policy `read` on the path,
and minted a token to use it. Every one of those was a fenced block. **This
guard exists because a document can be well-formed in the register that is read
and wrong in the register that is run**, which is why a second guard over one
file is not redundant.

The custody verdicts are not restated here either: they are read from the
document's own table AND compared with `POINTER_MATERIAL` in the code, so the
table, the type and the executed steps have to agree with each other rather than
each being separately plausible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from vendor_cp.deployment.signers import POINTER_MATERIAL, MaterialKind

DOSSIER = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "design"
    / "signing-identity-mint-dossier.md"
)

#: A heading naming the step where a key may legitimately be generated off this
#: workstation — the one place an identity with PUBLIC material is created.
_ON_TARGET = "ON the target"

_FENCE = re.compile(r"^```(\w*)\s*$")
_HEADING = re.compile(r"^#{2,3} (.+)$")
_ROW = re.compile(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|(.+)\|\s*$")
_CELL = re.compile(r"^`([^`]+)`$")
_POINTER_SLUG = re.compile(r"^secret/dotmac/platform-cp/([a-z-]+)-signing/[a-z]+$")
_KV_PUT = re.compile(r"^bao kv put (secret/\S+)")
_TOKEN_CREATE = re.compile(r"^bao token create -policy=platform-cp-([a-z-]+)-signing")
#: ANY well-formed grant. Narrowing this to platform-cp signing paths made
#: the licensing denials -- correct and load-bearing -- read as unparsable, so
#: the real document produced six refusals and the guard could never be green.
_POLICY_PATH = re.compile(
    r'^path\s+"([^"]+)"\s*\{\s*capabilities\s*=\s*\[([^\]]*)\]\s*\}\s*$'
)
_GENPKEY_OUT = re.compile(r"openssl genpkey .*-out (\S+)")
_FOR_LOOP = re.compile(r"^for \w+ in ([a-z0-9 -]+); do")
#: Every `bao` invocation this extractor understands. Anything else is refused
#: as unreadable rather than passing as clean — see the sensitivity test.
_KNOWN_BAO = (
    "kv put",
    "kv get",
    "policy write",
    "policy read",
    "token create",
    "token revoke",
)


class CeremonyRefusal(StrEnum):
    """Why the ceremony contradicts the custody it declares."""

    #: A `bao kv put` writes private material to a PUBLIC-material pointer.
    PRIVATE_MATERIAL_STORED = "PRIVATE_MATERIAL_STORED"
    #: A policy grants read on a PUBLIC-material pointer.
    READ_POLICY_GRANTED = "READ_POLICY_GRANTED"
    #: A token is minted for an identity this product may not hold.
    TOKEN_MINTED = "TOKEN_MINTED"
    #: A key for a PUBLIC-material identity is generated off the target.
    GENERATED_OFF_TARGET = "GENERATED_OFF_TARGET"
    #: A directive the extractor cannot parse. Never a pass.
    UNREADABLE_DIRECTIVE = "UNREADABLE_DIRECTIVE"
    #: The document's custody table disagrees with the code's declaration.
    CUSTODY_DISAGREES_WITH_CODE = "CUSTODY_DISAGREES_WITH_CODE"


@dataclass(frozen=True, slots=True)
class Finding:
    refusal: CeremonyRefusal
    identity: str
    line: str


def _slugs(text: str) -> dict[str, str]:
    """purpose -> pointer slug, read from the identity table's own pointers."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        # Per CELL. The identity table's rows begin with a number, so a
        # first-cell match would read none of them -- which is how an earlier
        # draft of this guard found no slugs, left `public` empty, and silently
        # skipped every rule that depends on it.
        inner = [
            _CELL.match(cell.strip()).group(1)  # type: ignore[union-attr]
            for cell in line.split("|")
            if _CELL.match(cell.strip())
        ]
        purposes = [t for t in inner if re.fullmatch(r"[a-z][a-z0-9_]*", t)]
        slugs = [m.group(1) for t in inner if (m := _POINTER_SLUG.match(t))]
        if len(purposes) == 1 and len(slugs) == 1:
            found[purposes[0]] = slugs[0]
    return found


def custody(text: str) -> dict[str, MaterialKind]:
    """purpose -> material kind, read from the custody table's verdict column."""
    verdicts: dict[str, MaterialKind] = {}
    for line in text.splitlines():
        row = _ROW.match(line)
        if not row or "obtain" in row.group(2):
            continue
        cells = [cell.strip() for cell in row.group(2).split("|")]
        verdict = cells[-1] if cells else ""
        if "NO" in verdict and "structurally" in verdict:
            verdicts[row.group(1)] = MaterialKind.PUBLIC
        elif "yes, by design" in verdict:
            verdicts[row.group(1)] = MaterialKind.PRIVATE
    return verdicts


def _blocks(text: str) -> list[tuple[str, str, list[str]]]:
    """(heading, language, lines) for every fenced block, in order."""
    out: list[tuple[str, str, list[str]]] = []
    heading, language, body = "", None, []
    for line in text.splitlines():
        fence = _FENCE.match(line)
        if fence and language is None:
            language, body = fence.group(1), []
            continue
        if line.strip() == "```" and language is not None:
            out.append((heading, language, body))
            language = None
            continue
        if language is not None:
            body.append(line)
        else:
            head = _HEADING.match(line)
            if head:
                heading = head.group(1)
    return out


def scan(text: str) -> list[Finding]:
    """Every way the executed register contradicts the declared custody."""
    slugs = _slugs(text)
    verdicts = custody(text)
    public = {
        slugs[purpose]
        for purpose, kind in verdicts.items()
        if kind is MaterialKind.PUBLIC and purpose in slugs
    }
    by_slug = {slug: purpose for purpose, slug in slugs.items()}
    findings: list[Finding] = []

    def flag(refusal: CeremonyRefusal, slug: str, line: str) -> None:
        findings.append(Finding(refusal, by_slug.get(slug, slug), line.strip()))

    for purpose, kind in verdicts.items():
        declared = POINTER_MATERIAL.get(purpose)
        if declared is not None and declared is not kind:
            findings.append(
                Finding(
                    CeremonyRefusal.CUSTODY_DISAGREES_WITH_CODE,
                    purpose,
                    f"table says {kind}, POINTER_MATERIAL says {declared}",
                )
            )

    for heading, language, body in _blocks(text):
        loop: list[str] = []
        pending: str | None = None
        for raw in body:
            line = raw.strip()
            if language == "hcl":
                if line.startswith("path "):
                    grant = _POLICY_PATH.match(line)
                    if not grant:
                        flag(CeremonyRefusal.UNREADABLE_DIRECTIVE, "", raw)
                        continue
                    granted = grant.group(1)
                    slug = next(
                        (s for s in public if f"/platform-cp/{s}-signing/" in granted),
                        None,
                    )
                    if slug and "read" in grant.group(2):
                        flag(CeremonyRefusal.READ_POLICY_GRANTED, slug, raw)
                continue
            if line.startswith("#") or not line:
                continue
            for_loop = _FOR_LOOP.match(line)
            if for_loop:
                loop = for_loop.group(1).split()
            if "openssl genpkey" in line and _ON_TARGET not in heading:
                out = _GENPKEY_OUT.search(line)
                names = (
                    loop
                    if out and "${" in out.group(1)
                    else ([out.group(1)] if out else [])
                )
                for name in names:
                    for slug in public:
                        if slug in name:
                            flag(CeremonyRefusal.GENERATED_OFF_TARGET, slug, raw)
            if line.startswith("bao "):
                if not any(line.startswith(f"bao {verb}") for verb in _KNOWN_BAO):
                    flag(CeremonyRefusal.UNREADABLE_DIRECTIVE, "", raw)
                    continue
                put = _KV_PUT.match(line)
                if put:
                    pending = put.group(1)
                token = _TOKEN_CREATE.match(line)
                if token and token.group(1) in public:
                    flag(CeremonyRefusal.TOKEN_MINTED, token.group(1), raw)
            if pending and "private_key_pem" in line:
                for slug in public:
                    if f"/{slug}-signing/" in pending:
                        flag(CeremonyRefusal.PRIVATE_MATERIAL_STORED, slug, raw)
            if not line.endswith("\\"):
                pending = None
    return findings


def _text() -> str:
    return DOSSIER.read_text(encoding="utf-8")


def _plant(old: str, new: str) -> str:
    text = _text()
    assert text.count(old) == 1, f"anchor is not unique: {old[:60]!r}"
    return text.replace(old, new)


def test_the_ceremony_does_not_contradict_its_custody_table() -> None:
    """The document as it stands. Everything below plants a defect into THIS."""
    assert scan(_text()) == []


def test_the_custody_table_and_the_code_declare_the_same_thing() -> None:
    """Three registers, not two: the table a reader reads, the type a caller
    imports, and the steps an operator runs. Two agreeing is not enough."""
    verdicts = custody(_text())
    assert verdicts, "no custody verdicts parsed; this guard would pass over nothing"
    assert set(verdicts) == set(POINTER_MATERIAL)
    for purpose, kind in verdicts.items():
        assert POINTER_MATERIAL[purpose] is kind, purpose
    assert (
        MaterialKind.PUBLIC in verdicts.values()
    ), "no identity is PUBLIC-material, so every rule below is vacuous"


def _only(findings: list[Finding], refusal: CeremonyRefusal) -> Finding:
    matching = [f for f in findings if f.refusal is refusal]
    assert len(matching) == 1, f"expected exactly one {refusal}, got {findings}"
    return matching[0]


def test_generating_the_target_key_on_the_workstation_is_refused() -> None:
    """Plant #1 of the four the merged document actually contained."""
    doctored = _plant(
        "for id in authorization dispatch release-evidence; do",
        "for id in authorization dispatch target-observation release-evidence; do",
    )
    finding = _only(scan(doctored), CeremonyRefusal.GENERATED_OFF_TARGET)
    assert finding.identity == "target_execution_observation"
    assert "genpkey" in finding.line


def test_storing_the_target_private_key_in_this_namespace_is_refused() -> None:
    """Plant #2. The exact `bao kv put` line #144 removed."""
    doctored = _plant(
        "  key_id=platform-cp-target-observation-2026-09 \\\n",
        "  key_id=platform-cp-target-observation-2026-09 \\\n"
        "  private_key_pem=@target-observation.key.pem \\\n",
    )
    finding = _only(scan(doctored), CeremonyRefusal.PRIVATE_MATERIAL_STORED)
    assert finding.identity == "target_execution_observation"
    assert "private_key_pem" in finding.line


def test_granting_read_on_the_target_pointer_is_refused() -> None:
    """Plant #3. A policy that would let this product fetch the key."""
    doctored = _plant(
        "# platform-cp-authorization-signing.hcl\n",
        "# platform-cp-authorization-signing.hcl\n"
        'path "secret/data/dotmac/platform-cp/target-observation-signing/primary"'
        ' { capabilities = ["read"] }\n',
    )
    finding = _only(scan(doctored), CeremonyRefusal.READ_POLICY_GRANTED)
    assert finding.identity == "target_execution_observation"
    assert "target-observation-signing" in finding.line


def test_minting_a_fourth_token_is_refused() -> None:
    """Plant #4, and the one that most needs to be a CHECK.

    A ceremony that quietly minted this token looks identical to one that did
    not, which is exactly why "no token line found" cannot be the pass
    condition on its own — see the unreadable test below.
    """
    doctored = _plant(
        "bao token create -policy=platform-cp-authorization-signing \\\n",
        "bao token create -policy=platform-cp-target-observation-signing \\\n"
        "  -period=720h -display-name=platform-cp-target-observation-signing\n"
        "bao token create -policy=platform-cp-authorization-signing \\\n",
    )
    finding = _only(scan(doctored), CeremonyRefusal.TOKEN_MINTED)
    assert finding.identity == "target_execution_observation"
    assert "token create" in finding.line


def test_the_four_defects_are_reported_separately_not_as_one() -> None:
    """All four at once must yield four distinct refusals. An aggregate would
    send an operator round the loop once per defect."""
    text = _text()
    text = text.replace(
        "for id in authorization dispatch release-evidence; do",
        "for id in authorization dispatch target-observation release-evidence; do",
    )
    text = text.replace(
        "  key_id=platform-cp-target-observation-2026-09 \\\n",
        "  key_id=platform-cp-target-observation-2026-09 \\\n"
        "  private_key_pem=@target-observation.key.pem \\\n",
    )
    text = text.replace(
        "# platform-cp-dispatch-signing.hcl\n",
        "# platform-cp-dispatch-signing.hcl\n"
        'path "secret/metadata/dotmac/platform-cp/target-observation-signing/primary"'
        ' { capabilities = ["read"] }\n',
    )
    text = text.replace(
        "bao token create -policy=platform-cp-dispatch-signing \\\n",
        "bao token create -policy=platform-cp-target-observation-signing \\\n"
        "bao token create -policy=platform-cp-dispatch-signing \\\n",
    )
    assert {f.refusal for f in scan(text)} == {
        CeremonyRefusal.GENERATED_OFF_TARGET,
        CeremonyRefusal.PRIVATE_MATERIAL_STORED,
        CeremonyRefusal.READ_POLICY_GRANTED,
        CeremonyRefusal.TOKEN_MINTED,
    }


def test_an_unreadable_directive_refuses_rather_than_passing_as_clean() -> None:
    """ABSENT must be distinguishable from UNPARSED.

    Every rule above passes by finding nothing. A block the extractor cannot
    read also contains nothing it recognises, so silence would mean the same as
    compliance — and a document could evade all four rules by being written in a
    form this parser does not understand.
    """
    unknown_verb = _plant(
        "bao policy write platform-cp-authorization-signing",
        "bao secrets enable -path=platform-cp kv-v2\n"
        "bao policy write platform-cp-authorization-signing",
    )
    finding = _only(scan(unknown_verb), CeremonyRefusal.UNREADABLE_DIRECTIVE)
    assert "bao secrets enable" in finding.line

    malformed_policy = _plant(
        "# platform-cp-dispatch-signing.hcl\n",
        "# platform-cp-dispatch-signing.hcl\n"
        'path "secret/data/dotmac/platform-cp/target-observation-signing/*" read\n',
    )
    malformed = _only(scan(malformed_policy), CeremonyRefusal.UNREADABLE_DIRECTIVE)
    assert "target-observation-signing" in malformed.line
