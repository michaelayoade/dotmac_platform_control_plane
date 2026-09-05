"""The kernel-lock workflow's refusals, each planted against.

`.github/workflows/kernel-lock.yml` holds `FORGEJO_READ_TOKEN` and resolves a
caller-supplied commit. Four defects were found in it before it had ever been
dispatched, and three of them were invisible precisely because the checks lived
inside `run:` blocks, where nothing can plant a defect against them:

1. the resolver tooling was loaded from the ref under resolution, so a dispatch
   against an untrusted commit executed that commit's composite action in a job
   holding the credential;
2. the drift gate compared `(name, version)` and file hashes, so an unrelated
   package repointed at a different index resolved clean;
3. the evidence scan was `grep -q -- "${TOKEN}"`, which with an unconfigured
   secret searches for the empty pattern — it cannot tell "no credential is
   present" from "there was no credential to look for";
4. the lock was uploaded without the manifest whose content-hash it carries.

Every refusal below is exercised against a planted violation, and each planted
violation has a near-miss beside it that must NOT be reported. `test_the_
comparison_this_replaced_could_not_see_a_repointed_source` keeps defect 2 as a
permanent negative control: it re-implements the old gate and shows it silent
on the plant the new one names.
"""

from __future__ import annotations

import base64
import re
import sys
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "kernel-lock.yml"
sys.path.insert(0, str(ROOT / "scripts"))

from kernel_lock import (  # noqa: E402
    INDEX_SOURCE_NAME,
    INDEX_URL,
    INDEX_USERNAME,
    KERNEL,
    REDACTED,
    Refusal,
    build_evidence,
    credential_encodings,
    credential_sightings,
    drift_problems,
    manifest_problems,
    pair_binding,
    replace_kernel_version,
    scrub,
    sha256_hex,
    sha256sums,
)

# ── fixtures for the lock comparison ────────────────────────────────────────


#: Positions in `_before()`: an ordinary public package, a package that
#: already carries a `[package.source]`, and the kernel itself.
ATTRS, CATALOGUE, KERNEL_ENTRY = 0, 1, 2


def _package(name: str, version: str, **extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "version": version,
        "description": f"{name}, for the comparison",
        "optional": False,
        "python-versions": ">=3.12",
        "groups": ["main"],
        "files": [
            {"file": f"{name}-{version}.whl", "hash": f"sha256:{name}-whl"},
            {"file": f"{name}-{version}.tar.gz", "hash": f"sha256:{name}-sdist"},
        ],
    }
    entry.update(extra)
    return entry


def _lock(packages: list[dict[str, Any]], content_hash: str) -> dict[str, Any]:
    return {
        "package": packages,
        "metadata": {
            "lock-version": "2.1",
            "python-versions": ">=3.12,<3.14",
            "content-hash": content_hash,
        },
    }


def _before() -> dict[str, Any]:
    return _lock(
        [
            _package("attrs", "24.2.0"),
            _package(
                "dotmac-release-catalog",
                "0.1.0a4",
                source={"type": "legacy", "url": INDEX_URL, "reference": "forgejo"},
            ),
            _package(KERNEL, "0.1.0a98"),
        ],
        "content-hash-before",
    )


def _after() -> dict[str, Any]:
    """The only clean shape: the kernel entry moved, the content-hash moved."""

    resolved = _before()
    resolved["package"][KERNEL_ENTRY] = _package(KERNEL, "0.1.0a99")
    resolved["metadata"]["content-hash"] = "content-hash-after"
    return resolved


def _plant(index: int, field: str, value: Any) -> dict[str, Any]:
    """A clean resolution with exactly one thing wrong with it."""

    resolved = _after()
    resolved["package"][index][field] = value
    return resolved


# ── the near-miss ───────────────────────────────────────────────────────────


def test_a_resolution_that_moved_only_the_kernel_is_accepted() -> None:
    """SENSITIVITY. A gate that refuses everything proves nothing about the
    thing it is supposed to catch, so the accepted shape is asserted first."""

    assert drift_problems(_before(), _after()) == []


# ── defect 2: the drift comparison sees the whole lock ──────────────────────


_ELSEWHERE = {
    "type": "legacy",
    "url": "https://elsewhere.example/simple",
    "reference": "forgejo",
}


def test_a_repointed_source_on_an_unrelated_package_is_named() -> None:
    """THE plant this repair exists for.

    Same name, same version, same files, different index. A package silently
    repointed at a host the tree does not otherwise name is a supply-chain
    substitution, and it arrived inside a change whose whole claim is that
    only the kernel moved.
    """

    resolved = _plant(CATALOGUE, "source", _ELSEWHERE)
    problems = drift_problems(_before(), resolved)
    assert problems, "a repointed source was not seen at all"
    assert any(
        "dotmac-release-catalog" in problem and "source" in problem
        for problem in problems
    ), problems


def _pre_repair_drift(before: dict[str, Any], after: dict[str, Any]) -> set[str]:
    """The comparison at origin/main, kept verbatim as a negative control."""

    def packages(lock: dict[str, Any]) -> dict[tuple[str, str], tuple[str, ...]]:
        return {
            (entry["name"], entry["version"]): tuple(
                sorted(item["hash"] for item in entry.get("files", []))
            )
            for entry in lock["package"]
        }

    before_map, after_map = packages(before), packages(after)
    moved = {name for name, _ in set(before_map) ^ set(after_map)}
    changed = {
        key[0]
        for key in set(before_map) & set(after_map)
        if before_map[key] != after_map[key]
    }
    return (moved | changed) - {KERNEL}


def test_the_comparison_this_replaced_could_not_see_a_repointed_source() -> None:
    """Why the repair was needed, as a check rather than as a claim."""

    resolved = _plant(CATALOGUE, "source", _ELSEWHERE)
    assert _pre_repair_drift(_before(), resolved) == set()
    assert drift_problems(_before(), resolved) != []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dependencies", {"anything": "*"}),
        ("extras", {"testing": ["pytest"]}),
        ("python-versions", ">=3.13"),
        ("optional", True),
        ("groups", ["main", "dev"]),
        ("description", "quietly rewritten"),
    ],
)
def test_every_other_field_of_an_unrelated_entry_is_compared(
    field: str, value: Any
) -> None:
    resolved = _plant(ATTRS, field, value)
    problems = drift_problems(_before(), resolved)
    named = [problem for problem in problems if "attrs" in problem]
    assert named, f"a changed `{field}` on an unrelated package was not named"
    assert field in named[0], named
    # And it was genuinely invisible before, so this row is a plant.
    assert _pre_repair_drift(_before(), resolved) == set()


def test_a_changed_file_hash_on_an_unrelated_package_is_named() -> None:
    swapped = [{"file": "attrs-24.2.0.whl", "hash": "sha256:swapped"}]
    resolved = _plant(ATTRS, "files", swapped)
    assert any("attrs" in problem for problem in drift_problems(_before(), resolved))


def test_an_added_or_removed_package_is_named() -> None:
    added = _after()
    added["package"].append(_package("left-pad", "1.0.0"))
    assert any("left-pad" in problem for problem in drift_problems(_before(), added))

    removed = _after()
    del removed["package"][0]
    assert any("attrs" in problem for problem in drift_problems(_before(), removed))


@pytest.mark.parametrize("field", ["lock-version", "python-versions"])
def test_lock_metadata_is_compared(field: str) -> None:
    resolved = _after()
    resolved["metadata"][field] = "rewritten"
    assert any(field in problem for problem in drift_problems(_before(), resolved))


def test_an_unchanged_content_hash_is_a_refusal() -> None:
    """The manifest edit MUST reach the lock. If it did not, the lock does not
    describe the manifest that will be applied beside it."""

    resolved = _after()
    resolved["metadata"]["content-hash"] = _before()["metadata"]["content-hash"]
    problems = drift_problems(_before(), resolved)
    assert any("content-hash" in problem for problem in problems), problems


def test_a_new_top_level_table_in_the_lock_is_named() -> None:
    resolved = _after()
    resolved["extras"] = {"surprise": ["anything"]}
    assert any("extras" in problem for problem in drift_problems(_before(), resolved))


def test_the_kernel_not_moving_is_still_a_refusal() -> None:
    resolved = _after()
    resolved["package"][KERNEL_ENTRY] = _package(KERNEL, "0.1.0a98")
    problems = drift_problems(_before(), resolved)
    assert any("did not move" in problem for problem in problems), problems


def test_two_entries_for_one_name_and_version_refuse() -> None:
    resolved = _after()
    resolved["package"].append(_package("attrs", "24.2.0"))
    with pytest.raises(Refusal):
        drift_problems(_before(), resolved)


# ── defect 1 support: the manifest may not misdirect the credential ─────────


def _manifest(**overrides: Any) -> dict[str, Any]:
    poetry: dict[str, Any] = {
        "dependencies": {
            "python": ">=3.12,<3.14",
            KERNEL: {"version": "0.1.0a99", "source": INDEX_SOURCE_NAME},
            "fastapi": ">=0.111",
        },
        "group": {"dev": {"dependencies": {"pytest": "^8.3"}}},
        "source": [
            {"name": INDEX_SOURCE_NAME, "url": INDEX_URL, "priority": "explicit"}
        ],
    }
    poetry.update(overrides)
    return {"tool": {"poetry": poetry}}


def test_the_repositorys_own_manifest_passes_the_guard() -> None:
    """NON-VACUITY. A guard nothing real can satisfy is a guard that has never
    been asked the question."""

    with (ROOT / "pyproject.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    declared = manifest["tool"]["poetry"]["dependencies"][KERNEL]["version"]
    assert manifest_problems(manifest, declared) == []


def test_a_synthetic_clean_manifest_passes() -> None:
    assert manifest_problems(_manifest(), "0.1.0a99") == []


def test_a_moved_index_url_under_the_same_source_name_is_refused() -> None:
    """The credential is keyed by source NAME. Moving the URL and keeping the
    name has Poetry post it to another host, with nothing untrusted executing
    anywhere — no amount of trusted tooling closes this one."""

    manifest = _manifest(
        source=[
            {
                "name": INDEX_SOURCE_NAME,
                "url": "https://attacker.example/simple",
                "priority": "explicit",
            }
        ]
    )
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("attacker.example" in problem for problem in problems), problems


def test_a_second_source_is_refused() -> None:
    manifest = _manifest(
        source=[
            {"name": INDEX_SOURCE_NAME, "url": INDEX_URL, "priority": "explicit"},
            {"name": "other", "url": "https://other.example/simple"},
        ]
    )
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("'other'" in problem for problem in problems), problems


def test_no_source_at_all_is_refused() -> None:
    assert manifest_problems(_manifest(source=[]), "0.1.0a99")


@pytest.mark.parametrize("key", ["path", "git", "url"])
def test_an_off_index_dependency_is_refused(key: str) -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = {key: "../elsewhere"}
    assert any(key in problem for problem in manifest_problems(manifest, "0.1.0a99"))


def test_an_off_index_dependency_in_a_GROUP_is_also_refused() -> None:
    """The traversal covers groups, not just the main table — a dev-group
    `path` dependency resolves in the same `poetry lock`."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["group"]["dev"]["dependencies"]["sneaky"] = {
        "path": "../elsewhere"
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("group.dev" in problem for problem in problems), problems


def test_requires_plugins_is_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["requires-plugins"] = {"anything": "*"}
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("plugin" in problem for problem in problems), problems


def test_a_kernel_version_that_is_not_the_one_asked_for_is_refused() -> None:
    assert manifest_problems(_manifest(), "0.1.0a100")


def test_a_kernel_dependency_not_bound_to_the_index_is_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"][KERNEL] = "0.1.0a99"
    assert any("bare constraint" in p for p in manifest_problems(manifest, "0.1.0a99"))


# ── the manifest edit ───────────────────────────────────────────────────────


def test_the_edit_moves_exactly_the_pin_in_the_real_manifest() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    edited = replace_kernel_version(text, "0.1.0a999")
    manifest = tomllib.loads(edited)
    assert manifest["tool"]["poetry"]["dependencies"][KERNEL]["version"] == "0.1.0a999"
    assert manifest["tool"]["poetry"]["dependencies"][KERNEL]["extras"] == [
        "testing",
        "licensing",
    ], "the edit changed more than the version"
    assert manifest_problems(manifest, "0.1.0a999") == []


@pytest.mark.parametrize(
    "text",
    [
        'dotmac-kernel = { version = "1" }\ndotmac-kernel = { version = "2" }\n',
        "nothing here declares it\n",
    ],
)
def test_the_edit_refuses_anything_but_one_declaration(text: str) -> None:
    with pytest.raises(Refusal):
        replace_kernel_version(text, "0.1.0a999")


# ── defect 3: the credential scan can refuse ────────────────────────────────

CREDENTIAL = "gho_A/b+c=d e9"


def test_an_absent_credential_is_a_refusal_in_its_own_right() -> None:
    """THE defect. `grep -q -- "${TOKEN}"` with an unset secret searches for
    the empty pattern: it matches every file and fails for the wrong reason, or
    matches nothing and reports the evidence clean. Neither answer is about the
    credential."""

    with pytest.raises(Refusal):
        credential_encodings("")


@pytest.mark.parametrize(
    "render",
    [
        lambda credential: credential,
        lambda credential: urllib.parse.quote(credential, safe=""),
        lambda credential: urllib.parse.quote_plus(credential),
        lambda credential: base64.b64encode(credential.encode()).decode(),
        lambda credential: base64.b64encode(
            f"{INDEX_USERNAME}:{credential}".encode()
        ).decode(),
    ],
)
def test_each_covered_encoding_is_found(tmp_path: Path, render: Any) -> None:
    log = tmp_path / "resolver.log"
    log.write_text(f"GET https://x/ -> {render(CREDENTIAL)} 200\n")
    assert credential_sightings([log], CREDENTIAL)


def test_a_near_miss_is_not_reported(tmp_path: Path) -> None:
    """SENSITIVITY the other way. A scan that fires on anything resembling the
    credential would make every run fail and teach the lane to ignore it."""

    log = tmp_path / "resolver.log"
    log.write_text(f"{CREDENTIAL[:-1]}\n{CREDENTIAL[1:]}\nghp_unrelated\n")
    assert credential_sightings([log], CREDENTIAL) == []


def test_scrubbing_removes_every_covered_encoding(tmp_path: Path) -> None:
    forms = credential_encodings(CREDENTIAL)
    text = "\n".join(f"{label}: {form}" for label, form in forms.items())
    scrubbed = scrub(text, CREDENTIAL)
    assert REDACTED in scrubbed
    log = tmp_path / "resolver.log"
    log.write_text(scrubbed)
    assert credential_sightings([log], CREDENTIAL) == []


# ── defect 4: the pair leaves together, bound ───────────────────────────────

_LOCK_TOML = """\
[[package]]
name = "dotmac-kernel"
version = "0.1.0a99"
files = [{file = "dotmac_kernel-0.1.0a99-py3-none-any.whl", hash = "sha256:a"}]

[metadata]
lock-version = "2.1"
python-versions = ">=3.12,<3.14"
content-hash = "the-content-hash"
"""


def _generated(tmp_path: Path, log_text: str = "Resolving dependencies...\n") -> Path:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[tool.poetry]\nname = "x"\n')
    lock = tmp_path / "poetry.lock"
    lock.write_text(_LOCK_TOML)
    log = tmp_path / "resolver.log"
    log.write_text(log_text)
    out = tmp_path / "evidence"
    sightings = build_evidence(
        out,
        manifest,
        lock,
        log,
        {"ref": "a" * 40, "kernel_version": "0.1.0a99", "workflow_run": "123"},
        CREDENTIAL,
    )
    assert sightings == []
    return out


def test_the_manifest_travels_with_the_lock(tmp_path: Path) -> None:
    """Defect 4. The lock's content-hash is derived from the manifest, so the
    lock alone describes a tree that does not exist."""

    out = _generated(tmp_path)
    names = {path.name for path in out.iterdir()}
    expected = {"pyproject.toml", "poetry.lock", "resolver.log"}
    expected |= {"coordinates.txt", "SHA256SUMS"}
    assert expected <= names, names


def test_the_pair_is_verifiable_from_the_artifact_alone(tmp_path: Path) -> None:
    out = _generated(tmp_path)
    sums = (out / "SHA256SUMS").read_text()
    for line in sums.splitlines():
        digest, name = line.split("  ", 1)
        if name in {"SHA256SUMS"}:
            continue
        assert sha256_hex((out / name).read_bytes()) == digest, name

    coordinates = (out / "coordinates.txt").read_text()
    digests = {
        name: sha256_hex((out / name).read_bytes())
        for name in ("pyproject.toml", "poetry.lock")
    }
    assert pair_binding(digests) in coordinates
    for name, digest in digests.items():
        assert digest in coordinates, name
    assert "the-content-hash" in coordinates
    assert "123" in coordinates, "the artifact does not name the run that made it"


def test_applying_one_half_of_the_pair_changes_the_binding(tmp_path: Path) -> None:
    """SENSITIVITY for the binding. Swapping either half must change it, or the
    value proves nothing about which two files belong together."""

    out = _generated(tmp_path)
    digests = {
        name: sha256_hex((out / name).read_bytes())
        for name in ("pyproject.toml", "poetry.lock")
    }
    baseline = pair_binding(digests)
    for name in digests:
        other = dict(digests)
        other[name] = sha256_hex(b"a different file")
        assert pair_binding(other) != baseline


def test_a_credential_in_the_lock_is_a_refusal_not_a_scrub(tmp_path: Path) -> None:
    """The resolver log is scrubbed because a URL may legitimately carry auth.
    The manifest and the lock are SCANNED: a credential there means something
    is wrong that redaction would hide."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(f'[tool.poetry]\nname = "{CREDENTIAL}"\n')
    lock = tmp_path / "poetry.lock"
    lock.write_text(_LOCK_TOML)
    log = tmp_path / "resolver.log"
    log.write_text("clean\n")
    sightings = build_evidence(
        tmp_path / "evidence",
        manifest,
        lock,
        log,
        {"ref": "a" * 40},
        CREDENTIAL,
    )
    assert any("pyproject.toml" in sighting for sighting in sightings), sightings


def test_a_credential_in_the_resolver_log_is_scrubbed(tmp_path: Path) -> None:
    out = _generated(tmp_path, log_text=f"auth={CREDENTIAL}\n")
    assert REDACTED in (out / "resolver.log").read_text()


def test_sha256sums_is_the_format_sha256sum_c_reads() -> None:
    body = sha256sums({"b.txt": "beef", "a.txt": "cafe"})
    assert body == "cafe  a.txt\nbeef  b.txt\n"


# ── defect 1: the workflow's own shape ──────────────────────────────────────


def _steps() -> list[str]:
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index("    steps:")
    blocks: list[list[str]] = []
    for line in lines[start + 1 :]:
        if line.startswith("      - "):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return ["\n".join(block) for block in blocks]


def _run_scripts() -> list[str]:
    """Every `run:` block body, dedented — what bash actually receives."""

    lines = WORKFLOW.read_text().splitlines()
    bodies: list[list[str]] = []
    inside: int | None = None
    for line in lines:
        match = re.match(r"^(\s*)-?\s*run: \|", line)
        if match:
            inside = len(match.group(1)) + 2
            bodies.append([])
            continue
        if inside is None:
            continue
        if line.strip() and not line.startswith(" " * inside):
            inside = None
            continue
        bodies.append(bodies.pop() + [line])
    return ["\n".join(body) for body in bodies]


def test_the_trusted_checkout_comes_first_and_owns_the_workspace_root() -> None:
    """Defect 1. Local actions and scripts resolve from `$GITHUB_WORKSPACE`, so
    whatever is checked out at the root is the code that runs. It must be the
    commit that defines this workflow, never the ref under resolution."""

    checkouts = [step for step in _steps() if "actions/checkout@" in step]
    assert len(checkouts) == 2, "the two-checkout shape is the repair"
    trusted, untrusted = checkouts
    assert "ref: ${{ github.sha }}" in trusted
    assert "path:" not in trusted, "the trusted checkout must own the root"
    assert "ref: ${{ inputs.ref }}" in untrusted
    assert "path: work" in untrusted, "the ref under resolution must not be the root"


def test_no_local_action_runs_before_the_trusted_checkout() -> None:
    """A `uses: ./...` before the root is populated, or after the untrusted ref
    has been checked out over it, is the original defect returning."""

    steps = _steps()
    trusted = next(
        index
        for index, step in enumerate(steps)
        if "actions/checkout@" in step and "github.sha" in step
    )
    untrusted = next(
        index
        for index, step in enumerate(steps)
        if "actions/checkout@" in step and "inputs.ref" in step
    )
    local = [index for index, step in enumerate(steps) if "uses: ./" in step]
    assert local, "the pinned Poetry bootstrap is a local action; it should be here"
    assert all(index > trusted for index in local)
    assert untrusted > trusted, "the untrusted checkout preceded the trusted one"


def test_no_step_holds_the_credential_before_the_manifest_is_judged() -> None:
    """The other half of defect 1. Trusted tooling is necessary and not
    sufficient: `poetry lock` reads a manifest the ref owns, and Poetry keys
    HTTP credentials by source NAME. Nothing may hold the credential until
    `manifest-guard` has ruled on where that name points."""

    steps = _steps()
    guard = next(i for i, step in enumerate(steps) if "manifest-guard" in step)
    holders = [
        i for i, step in enumerate(steps) if "secrets.FORGEJO_READ_TOKEN" in step
    ]
    assert holders, "no step holds the credential; this workflow cannot resolve"
    assert all(i > guard for i in holders), holders


def test_the_ref_under_resolution_is_only_ever_read_from_work() -> None:
    """Anything the untrusted tree supplies is addressed through `work/`, and
    the two scripts that judge it are addressed WITHOUT it."""

    scripts = "\n".join(_run_scripts())
    assert "python scripts/kernel_lock.py" in scripts
    assert "python work/scripts/kernel_lock.py" not in scripts
    for addressed in ("work/pyproject.toml", "work/poetry.lock"):
        assert addressed in scripts


def _interpolated_inputs(bodies: list[str]) -> list[str]:
    return [
        line
        for body in bodies
        for line in body.splitlines()
        if "${{" in line and "inputs." in line
    ]


def test_no_workflow_input_is_interpolated_into_a_shell_script() -> None:
    """Defect 3's third part. Both inputs are regex-validated in step 1, so a
    direct interpolation was not exploitable — but a sink whose safety rests on
    a check somewhere else is one deleted check away from being a sink. They
    cross as `env:` instead."""

    offenders = _interpolated_inputs(_run_scripts())
    assert offenders == [], offenders


def test_the_interpolation_check_would_catch_one() -> None:
    """SENSITIVITY. The assertion above passes over a clean file, which proves
    nothing about the assertion, and `_run_scripts` is a hand-rolled parser."""

    planted = 'echo "ref ${{ inputs.ref }}"\necho safe\n'
    assert _interpolated_inputs([planted]) == ['echo "ref ${{ inputs.ref }}"']
    assert _interpolated_inputs(["echo safe\n"]) == []


def test_the_run_block_parser_actually_found_the_scripts() -> None:
    """SENSITIVITY for the parser itself: a parser that returns nothing makes
    every check above pass."""

    bodies = _run_scripts()
    assert len(bodies) >= 6, len(bodies)
    assert any("poetry lock" in body for body in bodies)


def test_the_credential_is_wired_the_way_the_precedent_wires_it() -> None:
    text = WORKFLOW.read_text()
    assert "POETRY_HTTP_BASIC_FORGEJO_USERNAME: ci-reader" in text
    assert "secrets.FORGEJO_READ_TOKEN" in text
    # No run-time secret fetch. OpenBao owns the projection and its rotation;
    # this workflow consumes the repository secret it is projected into.
    assert "bao read" not in text
    assert "vault read" not in text
    assert "secret/dotmac/forgejo/read-token" in text


def test_the_workflow_never_commits_or_opens_a_pull_request() -> None:
    text = WORKFLOW.read_text()
    assert "permissions:\n  contents: read\n" in text
    for forbidden in ("git commit", "git push", "gh pr", "peter-evans"):
        assert forbidden not in text, forbidden


def test_the_workflow_and_the_module_name_one_index() -> None:
    assert INDEX_URL in WORKFLOW.read_text()


def test_it_is_dispatch_only() -> None:
    text = WORKFLOW.read_text()
    assert "workflow_dispatch:" in text
    for trigger in ("\n  push:", "\n  pull_request:", "\n  schedule:"):
        assert trigger not in text, trigger
