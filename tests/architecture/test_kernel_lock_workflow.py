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

An independent review of that repair then found credential-bound paths its
tests did not reach, and this file grew the plants for them:

5. `manifest_problems` refused off-index dependencies only in the forms it
   happened to look at — not `file`, not a LIST of constraint tables, not
   legacy `[tool.poetry.dev-dependencies]`, not PEP 621 `[project]`, not
   PEP 735 `[dependency-groups]`. An omitted form bypassed the guard entirely;
6. a candidate `poetry.toml` configured the Poetry that was about to resolve
   the candidate;
7. `actions/checkout` wrote the workflow token into `.git/config` of the
   UNTRUSTED tree;
8. `resolver.log` was uploaded on the strength of a scan its own docstring
   said could not prove absence;
9. the drift gate exempted the `dotmac-kernel` entry ENTIRELY, so the one entry
   the change is about was the one place a repointed source or an added
   dependency could arrive unread;
10. the simple-index links the job downloaded were index-controlled and
    unvalidated, with `--netrc` in play;
11. the credential and the resolver shared a job, so a package build backend
    executed with the credential in reach.

`test_the_comparison_this_replaced_could_not_see_a_repointed_source` keeps
defect 2 as a permanent negative control: it re-implements the old gate and
shows it silent on the plant the new one names.
"""

from __future__ import annotations

import base64
import json
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
    ARTIFACT_ORIGIN,
    INDEX_SOURCE_NAME,
    INDEX_URL,
    INDEX_USERNAME,
    KERNEL,
    OFF_INDEX_DEPENDENCY_KEYS,
    Refusal,
    acquisition_plan,
    approved_artifact_url,
    artifact_belongs_to,
    build_evidence,
    checkout_problems,
    credential_encodings,
    credential_sightings,
    curl_argv,
    drift_problems,
    hash_problems,
    index_links,
    kernel_artifact_names,
    manifest_problems,
    pair_binding,
    point_at_mirror,
    replace_kernel_version,
    restore_index_url,
    set_content_hash,
    sha256_hex,
    sha256sums,
    transfer_problems,
)

# ── fixtures for the lock comparison ────────────────────────────────────────


#: Positions in `_before()`: an ordinary public package, a package that
#: already carries a `[package.source]`, and the kernel itself.
ATTRS, CATALOGUE, KERNEL_ENTRY = 0, 1, 2

_INDEX_SOURCE = {"type": "legacy", "url": INDEX_URL, "reference": INDEX_SOURCE_NAME}


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
            _package("dotmac-release-catalog", "0.1.0a4", source=_INDEX_SOURCE),
            _package(KERNEL, "0.1.0a98", source=_INDEX_SOURCE),
        ],
        "content-hash-before",
    )


def _after() -> dict[str, Any]:
    """The only clean shape: the kernel entry moved, the content-hash moved."""

    resolved = _before()
    resolved["package"][KERNEL_ENTRY] = _package(
        KERNEL, "0.1.0a99", source=_INDEX_SOURCE
    )
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


# ── AMENDMENT 5: the kernel entry is not a blank cheque either ──────────────


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", _ELSEWHERE),
        ("dependencies", {"anything": "*"}),
        ("extras", {"surprise": ["anything"]}),
        ("optional", True),
        ("groups", ["main", "dev"]),
        ("python-versions", ">=3.13"),
        ("description", "quietly rewritten"),
    ],
)
def test_metadata_drift_on_the_kernel_entry_itself_is_refused(
    field: str, value: Any
) -> None:
    """THE plant for the review's fifth finding.

    The gate compared every entry EXCEPT this one, and then let this one change
    arbitrarily. So the single entry the whole change is about was the one place
    a repointed source, a widened `python-versions`, an added dependency table
    or a flipped `optional` could arrive unread — inside a diff whose entire
    claim is "the kernel moved".
    """

    resolved = _plant(KERNEL_ENTRY, field, value)
    problems = drift_problems(_before(), resolved)
    named = [problem for problem in problems if KERNEL in problem]
    assert named, f"a changed `{field}` on the kernel entry was not named"
    assert any(field in problem for problem in named), named


def test_the_kernel_may_still_move_its_version_and_its_files() -> None:
    """SENSITIVITY the other way. A gate that refused a moved `files` list
    would refuse every real run, which is the whole purpose of the workflow."""

    resolved = _after()
    resolved["package"][KERNEL_ENTRY]["files"] = [
        {"file": "dotmac_kernel-0.1.0a99-py3-none-any.whl", "hash": "sha256:new"}
    ]
    assert drift_problems(_before(), resolved) == []


def test_a_kernel_resolved_from_another_index_is_refused() -> None:
    resolved = _after()
    resolved["package"][KERNEL_ENTRY]["source"] = _ELSEWHERE
    problems = drift_problems(_before(), resolved)
    assert any("elsewhere.example" in problem for problem in problems), problems


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
    resolved["package"][KERNEL_ENTRY] = _package(
        KERNEL, "0.1.0a98", source=_INDEX_SOURCE
    )
    problems = drift_problems(_before(), resolved)
    assert any("did not move" in problem for problem in problems), problems


def test_two_entries_for_one_name_and_version_refuse() -> None:
    resolved = _after()
    resolved["package"].append(_package("attrs", "24.2.0"))
    with pytest.raises(Refusal):
        drift_problems(_before(), resolved)


# ── the manifest may not misdirect the credential ───────────────────────────


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


# ── AMENDMENT 1: every Poetry dependency form, one plant each ───────────────


@pytest.mark.parametrize("key", sorted(OFF_INDEX_DEPENDENCY_KEYS))
def test_an_off_index_dependency_is_refused(key: str) -> None:
    """`file` is the one this list was missing. It is a DISTINCT key from
    `path` — `Factory.create_dependency` dispatches it three branches earlier —
    so a guard that enumerated `path`, `git`, `url` walked past it."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = {key: "../elsewhere"}
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any(f"`{key}`" in problem for problem in problems), (key, problems)


@pytest.mark.parametrize("key", sorted(OFF_INDEX_DEPENDENCY_KEYS))
def test_an_off_index_dependency_inside_a_LIST_of_constraints_is_refused(
    key: str,
) -> None:
    """A multiple-constraints dependency is a LIST of tables, and Poetry
    resolves every entry in it. A traversal that only ever looked at a `dict`
    hit `isinstance(spec, dict)` and `continue`d straight past this."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = [
        {"version": "^1.0", "python": ">=3.12"},
        {key: "https://elsewhere.example/x.tar.gz", "python": "<3.12"},
    ]
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("sneaky[1]" in problem and f"`{key}`" in problem for problem in problems)


def test_a_list_of_ordinary_constraints_is_accepted() -> None:
    """SENSITIVITY. Multiple constraints are a legitimate, documented form."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["fine"] = [
        {"version": "<=1.9", "python": ">=3.12,<3.13"},
        {"version": "^2.0", "python": ">=3.13"},
    ]
    assert manifest_problems(manifest, "0.1.0a99") == []


def test_an_off_index_dependency_in_a_GROUP_is_also_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["group"]["dev"]["dependencies"]["sneaky"] = {
        "path": "../elsewhere"
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("group.dev" in problem for problem in problems), problems


def test_an_off_index_dependency_in_LEGACY_dev_dependencies_is_refused() -> None:
    """`[tool.poetry.dev-dependencies]` is the pre-1.2 spelling. Poetry still
    reads it — `Factory` adds it to the `dev` group explicitly — and it is one
    of the keys the lock's own content-hash covers. The traversal read
    `dependencies` and `group.*.dependencies` and nothing else."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dev-dependencies"] = {
        "sneaky": {"git": "https://elsewhere.example/x.git"}
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("dev-dependencies.sneaky" in problem for problem in problems), problems


@pytest.mark.parametrize(
    "requirement",
    [
        "sneaky @ https://elsewhere.example/x-1.0.tar.gz",
        "sneaky @ file:///tmp/x-1.0.tar.gz",
        "sneaky @ git+https://elsewhere.example/x.git",
    ],
)
def test_a_pep_621_direct_reference_is_refused(requirement: str) -> None:
    """PEP 621 dependencies are STRINGS, so every off-index form arrives as a
    direct reference instead of as a table. And `[project]` may sit beside
    `[tool.poetry.dependencies]` — the documented enrichment shape — so the
    kernel pin can look untouched while `[project]` supplies anything it likes.
    """

    manifest = _manifest()
    manifest["project"] = {"name": "x", "dependencies": [requirement]}
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("project.dependencies[0]" in problem for problem in problems), problems


def test_a_pep_621_optional_dependency_direct_reference_is_refused() -> None:
    manifest = _manifest()
    manifest["project"] = {
        "name": "x",
        "optional-dependencies": {
            "extra": ["sneaky @ https://elsewhere.example/x-1.0.tar.gz"]
        },
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any(
        "project.optional-dependencies.extra[0]" in problem for problem in problems
    ), problems


def test_an_ordinary_pep_621_requirement_is_accepted() -> None:
    """SENSITIVITY. A PEP 508 requirement with a marker is not a direct
    reference, and a guard that refused one would refuse the modern layout."""

    manifest = _manifest()
    manifest["project"] = {
        "name": "x",
        "dependencies": ["requests (>=2.23.0,<3.0.0) ; python_version >= '3.12'"],
        "optional-dependencies": {"extra": ["rich>=13"]},
    }
    assert manifest_problems(manifest, "0.1.0a99") == []


def test_a_pep_735_dependency_group_direct_reference_is_refused() -> None:
    """`[dependency-groups]` is a top-level table Poetry 2 reads, and it is one
    of the inputs to the lock's content-hash. It is neither under `tool.poetry`
    nor under `project`, so a traversal of those two never saw it."""

    manifest = _manifest()
    manifest["dependency-groups"] = {
        "typing": ["sneaky @ https://elsewhere.example/x-1.0.tar.gz"]
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("dependency-groups.typing[0]" in problem for problem in problems)


def test_an_ordinary_pep_735_group_is_accepted() -> None:
    manifest = _manifest()
    manifest["dependency-groups"] = {
        "typing": ["mypy>=1.11", {"include-group": "test"}],
        "test": ["pytest>=8"],
    }
    assert manifest_problems(manifest, "0.1.0a99") == []


def test_an_unrecognised_constraint_key_is_refused() -> None:
    """The point is the NEXT form. Enumerate what is understood and refuse
    what is not, rather than allowing anything that fails to match a known-bad
    pattern — the latter is how `file` got through."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = {
        "version": "^1.0",
        "hg": "https://elsewhere.example/x",
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("unrecognised key `hg`" in problem for problem in problems), problems


def test_a_dependencies_table_at_an_unknown_PATH_is_refused() -> None:
    """A form that does not exist yet. The guard refuses a `dependenc`-named
    table it does not traverse instead of walking past it."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["future-dependencies"] = {"sneaky": {"path": "../x"}}
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any(
        "tool.poetry.future-dependencies" in problem and "traverse" in problem
        for problem in problems
    ), problems


def test_every_table_the_guard_traverses_is_accepted_when_ordinary() -> None:
    """SENSITIVITY for the refuse-what-you-do-not-recognise rule: each path it
    DOES traverse must not itself be reported as unrecognised."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dev-dependencies"] = {"black": "^24"}
    manifest["tool"]["poetry"]["group"]["typing"] = {
        "optional": True,
        "include-groups": ["dev"],
        "dependencies": {"mypy": "^1.11"},
    }
    manifest["project"] = {"name": "x", "dependencies": ["requests>=2"]}
    manifest["dependency-groups"] = {"docs": ["mkdocs>=1"]}
    assert manifest_problems(manifest, "0.1.0a99") == []


def test_an_unrecognised_group_key_is_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["group"]["dev"]["surprise"] = True
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("unrecognised key `surprise`" in problem for problem in problems)


def test_a_bare_constraint_that_is_not_a_version_is_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = (
        "https://elsewhere.example/x-1.0.tar.gz"
    )
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("not a plain version constraint" in p for p in problems), problems


def test_a_dependency_bound_to_an_unknown_source_is_refused() -> None:
    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["sneaky"] = {
        "version": "^1.0",
        "source": "other",
    }
    problems = manifest_problems(manifest, "0.1.0a99")
    assert any("does not hold a credential" in problem for problem in problems)


# ── AMENDMENT 2: a candidate may supply the manifest, not the config ────────


def test_a_candidate_poetry_toml_is_refused(tmp_path: Path) -> None:
    """THE plant. `poetry.toml` is Poetry's LOCAL configuration file, read from
    the project directory by the resolver that is about to run against that
    tree: `certificates.<repository>.cert = false` turns off TLS verification,
    `installer.no-binary` forces source distributions and so build-backend
    execution, `keyring.enabled` changes where credentials come from.

    The chosen resolution is REFUSAL, not an allowlist of settings — an
    allowlist is a second thing to keep in sync with Poetry, and the tree under
    resolution has no legitimate need to configure the tool that judges it. The
    resolver job additionally runs with a `POETRY_CONFIG_DIR` it created
    itself; that is belt, and this is brace.
    """

    (tmp_path / "poetry.toml").write_text("[certificates]\n")
    problems = checkout_problems(tmp_path)
    assert any("poetry.toml" in problem for problem in problems), problems


def test_a_checkout_without_one_is_clean(tmp_path: Path) -> None:
    """SENSITIVITY. This repository's own checkout has no `poetry.toml`."""

    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "x"\n')
    assert checkout_problems(tmp_path) == []
    assert checkout_problems(ROOT) == []


# ── AMENDMENT 6: the index is data, and its links are validated ─────────────

_PAGE = f"{INDEX_URL}/dotmac-kernel/"


def test_an_ordinary_relative_index_link_is_accepted() -> None:
    """SENSITIVITY first: a simple index normally carries relative hrefs, and a
    validator that refused them would refuse every real page."""

    url = approved_artifact_url("../../files/dotmac_kernel-1.whl#sha256=ab", _PAGE)
    assert url.startswith(f"{ARTIFACT_ORIGIN}/api/packages/dotmac/pypi/files/")


def test_an_absolute_link_on_the_approved_origin_is_accepted() -> None:
    href = f"{ARTIFACT_ORIGIN}/api/packages/dotmac/pypi/files/x.whl"
    assert approved_artifact_url(href, _PAGE) == href


@pytest.mark.parametrize(
    ("href", "why"),
    [
        ("https://elsewhere.example/x.whl", "off-origin"),
        ("http://registry.dotmac.io/api/packages/dotmac/pypi/files/x.whl", "http"),
        ("../../../../../../etc/passwd", "path traversal"),
        (
            "https://ci-reader:leaked@registry.dotmac.io/api/packages/"
            "dotmac/pypi/files/x.whl",
            "userinfo",
        ),
        ("https://registry.dotmac.io/other/x.whl", "outside the path prefix"),
        ("", "empty"),
    ],
)
def test_an_index_controlled_link_that_is_not_approved_refuses(
    href: str, why: str
) -> None:
    """THE plants. Every href on a simple index page is chosen by the index, and
    `curl --netrc` offers the credential to whatever host it is pointed at whose
    name is in the netrc file. So the destination is validated BEFORE the
    transfer."""

    with pytest.raises(Refusal):
        approved_artifact_url(href, _PAGE)


def test_a_redirect_is_refused_rather_than_followed() -> None:
    """THE redirect policy, stated as a check.

    `curl` following a redirect while `--netrc` is in play is a credential-
    disclosure path: the second destination is chosen by whatever answered the
    first. The policy here is that redirects are NOT followed at all, so there
    is no hop to re-validate — `curl_argv` carries no `--location`, and any
    status but 200 refuses.
    """

    argv = curl_argv("https://registry.dotmac.io/x", Path("artifact.whl"))
    assert "-L" not in argv and "--location" not in argv, argv
    assert "--max-redirs" in argv and argv[argv.index("--max-redirs") + 1] == "0"
    assert argv[argv.index("--proto") + 1] == "=https"

    problems = transfer_problems("https://registry.dotmac.io/x", "302")
    assert any("redirect" in problem.lower() for problem in problems), problems
    assert transfer_problems("https://registry.dotmac.io/x", "200") == []
    assert transfer_problems("https://registry.dotmac.io/x", "404") != []

    # And were a hop ever followed, this is the validator it would have to
    # pass. A redirect to an unapproved host does not survive it.
    with pytest.raises(Refusal):
        approved_artifact_url("https://evil.example/dotmac_kernel-1.whl", _PAGE)


def test_the_link_parser_finds_what_a_simple_index_carries() -> None:
    """SENSITIVITY for the parser: one that returned nothing would make every
    validation above vacuous, and would also make a package look unpublished."""

    page = (
        '<html><body><a href="../../files/a.whl#sha256=1">a</a>'
        '<a href="https://elsewhere.example/b.whl">b</a></body></html>'
    )
    assert index_links(page) == [
        "../../files/a.whl#sha256=1",
        "https://elsewhere.example/b.whl",
    ]


# ── AMENDMENT 7: the bundle is closed, and a gap refuses ────────────────────


def _plan_manifest() -> dict[str, Any]:
    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["dotmac-release-catalog"] = {
        "version": "0.1.0a4",
        "source": INDEX_SOURCE_NAME,
    }
    return manifest


def test_the_bundle_closes_over_every_private_package() -> None:
    plan = acquisition_plan(_plan_manifest(), _before(), "0.1.0a99")
    assert plan == {KERNEL: "0.1.0a99", "dotmac-release-catalog": "0.1.0a4"}


def test_a_private_package_the_manifest_never_names_is_still_bundled() -> None:
    """A transitive private dependency appears only in the lock. Leaving it out
    of the bundle would make the resolver reach for the index it has no
    credential for — which fails, correctly, but for a reason nobody could read.
    """

    lock = _before()
    lock["package"].append(
        _package("dotmac-approvals", "0.1.0a5", source=_INDEX_SOURCE)
    )
    plan = acquisition_plan(_manifest(), lock, "0.1.0a99")
    assert plan["dotmac-approvals"] == "0.1.0a5"


def test_a_private_dependency_that_is_not_an_exact_pin_refuses() -> None:
    """The bundle can only be CLOSED around versions known before resolution
    starts. Deciding what a range resolves to would be this module inventing
    the answer the resolver exists to produce."""

    manifest = _manifest()
    manifest["tool"]["poetry"]["dependencies"]["dotmac-approvals"] = {
        "version": "^0.1",
        "source": INDEX_SOURCE_NAME,
    }
    with pytest.raises(Refusal):
        acquisition_plan(manifest, _before(), "0.1.0a99")


def test_the_repositorys_real_manifest_and_lock_produce_a_closed_plan() -> None:
    """NON-VACUITY, against the two real files."""

    with (ROOT / "pyproject.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    with (ROOT / "poetry.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    plan = acquisition_plan(manifest, lock, "0.1.0a999")
    assert plan[KERNEL] == "0.1.0a999"
    locked_private = {
        entry["name"]
        for entry in lock["package"]
        if entry.get("source", {}).get("reference") == INDEX_SOURCE_NAME
    }
    assert locked_private <= set(plan), locked_private - set(plan)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("dotmac_kernel-0.1.0a99-py3-none-any.whl", True),
        ("dotmac_kernel-0.1.0a99.tar.gz", True),
        ("dotmac_kernel-0.1.0a990.tar.gz", False),
        ("dotmac_kernel_extra-0.1.0a99.tar.gz", False),
        ("dotmac_kernel-0.1.0a98.tar.gz", False),
    ],
)
def test_an_artifact_is_matched_to_its_exact_version(
    filename: str, expected: bool
) -> None:
    assert artifact_belongs_to(filename, KERNEL, "0.1.0a99") is expected


def test_the_lock_must_name_the_bytes_that_were_downloaded() -> None:
    version = "0.1.0a99"
    names = sorted(kernel_artifact_names(version))
    digests = {names[0]: "aa", names[1]: "bb"}
    lock = {
        "package": [
            {
                "name": KERNEL,
                "version": version,
                "source": _INDEX_SOURCE,
                "files": [
                    {"file": names[0], "hash": "sha256:aa"},
                    {"file": names[1], "hash": "sha256:bb"},
                ],
            }
        ]
    }
    assert hash_problems(lock, digests, version) == []

    swapped = json.loads(json.dumps(lock))
    swapped["package"][0]["files"][0]["hash"] = "sha256:not-the-bytes"
    problems = hash_problems(swapped, digests, version)
    assert any("the published bytes hash to" in problem for problem in problems)

    wrong_version = json.loads(json.dumps(lock))
    wrong_version["package"][0]["version"] = "0.1.0a98"
    assert hash_problems(wrong_version, digests, version)

    invented = json.loads(json.dumps(lock))
    invented["package"][0]["files"].append(
        {"file": "dotmac_kernel-0.1.0a99-py2-none-any.whl", "hash": "sha256:zz"}
    )
    assert hash_problems(invented, digests, version)


def test_the_mirror_swap_is_reversible_and_refuses_an_ambiguous_manifest() -> None:
    """The manifest that LEAVES must be the manifest a consumer applies, so the
    loopback URL must not survive into the artifact."""

    mirror = "http://127.0.0.1:8899/simple"
    text = f'[[tool.poetry.source]]\nname = "forgejo"\nurl = "{INDEX_URL}"\n'
    aimed = point_at_mirror(text, mirror)
    assert mirror in aimed and INDEX_URL not in aimed
    assert restore_index_url(aimed, mirror) == text

    with pytest.raises(Refusal):
        point_at_mirror(text + text, mirror)
    with pytest.raises(Refusal):
        point_at_mirror("nothing here names the index", mirror)
    with pytest.raises(Refusal):
        restore_index_url(text, mirror)


def test_the_content_hash_line_is_replaced_exactly_once() -> None:
    """Restoring the source URL changes the manifest, and `source` is one of
    the keys Poetry's content-hash covers — so the hash the offline resolution
    wrote describes the MIRROR manifest. `poetry check --lock` in the workflow
    is what proves the replacement; this proves the replacement is unambiguous.
    """

    lock = '[metadata]\nlock-version = "2.1"\ncontent-hash = "old"\n'
    assert 'content-hash = "new"' in set_content_hash(lock, "new")
    with pytest.raises(Refusal):
        set_content_hash(lock + 'content-hash = "second"\n', "new")
    with pytest.raises(Refusal):
        set_content_hash("[metadata]\n", "new")


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
    subject = tmp_path / "pyproject.toml"
    subject.write_text(f'[tool.poetry]\nname = "{render(CREDENTIAL)}"\n')
    assert credential_sightings([subject], CREDENTIAL)


def test_a_near_miss_is_not_reported(tmp_path: Path) -> None:
    """SENSITIVITY the other way. A scan that fires on anything resembling the
    credential would make every run fail and teach the lane to ignore it."""

    subject = tmp_path / "pyproject.toml"
    subject.write_text(f"{CREDENTIAL[:-1]}\n{CREDENTIAL[1:]}\nghp_unrelated\n")
    assert credential_sightings([subject], CREDENTIAL) == []


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


def _generated(tmp_path: Path) -> Path:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[tool.poetry]\nname = "x"\n')
    lock = tmp_path / "poetry.lock"
    lock.write_text(_LOCK_TOML)
    out = tmp_path / "evidence"
    sightings = build_evidence(
        out,
        manifest,
        lock,
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
    assert names == {"pyproject.toml", "poetry.lock", "coordinates.txt", "SHA256SUMS"}


def test_no_scanned_only_file_is_uploaded(tmp_path: Path) -> None:
    """AMENDMENT 4, and it is a property of the artifact rather than of a step.

    The resolver log was uploaded scrubbed of the credential's known encodings,
    and `credential_encodings`' own docstring conceded what it could not see: a
    credential split across lines, compressed or archived bytes, a hex
    rendering, non-UTF-8 bytes, base64 at a non-zero offset inside a larger
    blob. A file whose scan is known-incomplete does not become safe by being
    scanned. Nothing here is uploaded on the strength of a scan: the two files
    present are ones whose answer to a sighting is REFUSAL.
    """

    out = _generated(tmp_path)
    assert not list(out.glob("*.log"))
    assert "resolver" not in {path.stem for path in out.iterdir()}
    prose = (out / "coordinates.txt").read_text()
    assert "resolver log is deliberately NOT here" in prose


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


def test_a_credential_in_the_pair_is_a_refusal_not_a_scrub(tmp_path: Path) -> None:
    """Nothing in the artifact is redacted any more. The manifest and the lock
    are SCANNED, and a sighting in either means something is wrong that
    redaction would hide."""

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(f'[tool.poetry]\nname = "{CREDENTIAL}"\n')
    lock = tmp_path / "poetry.lock"
    lock.write_text(_LOCK_TOML)
    sightings = build_evidence(
        tmp_path / "evidence", manifest, lock, {"ref": "a" * 40}, CREDENTIAL
    )
    assert any("pyproject.toml" in sighting for sighting in sightings), sightings


def test_sha256sums_is_the_format_sha256sum_c_reads() -> None:
    body = sha256sums({"b.txt": "beef", "a.txt": "cafe"})
    assert body == "cafe  a.txt\nbeef  b.txt\n"


# ── the workflow's own shape ────────────────────────────────────────────────


def _jobs() -> dict[str, list[str]]:
    """job name -> its step blocks, in order. A hand-rolled parser, so
    `test_the_workflow_parser_found_the_jobs` keeps it honest."""

    lines = WORKFLOW.read_text().splitlines()
    start = lines.index("jobs:")
    jobs: dict[str, list[list[str]]] = {}
    current: str | None = None
    in_steps = False
    for line in lines[start + 1 :]:
        header = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if header:
            current = header.group(1)
            jobs[current] = []
            in_steps = False
            continue
        if current is None:
            continue
        if line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            jobs[current].append([line])
        elif jobs[current]:
            jobs[current][-1].append(line)
    return {
        name: ["\n".join(block) for block in blocks] for name, blocks in jobs.items()
    }


def _needs(job: str) -> set[str]:
    """The transitive `needs:` closure of a job."""

    text = WORKFLOW.read_text()
    direct: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        header = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if header:
            current = header.group(1)
        elif current and line.startswith("    needs: "):
            direct[current] = line.split("needs: ", 1)[1].strip()
    closure: set[str] = set()
    frontier = [job]
    while frontier:
        name = frontier.pop()
        parent = direct.get(name)
        if parent and parent not in closure:
            closure.add(parent)
            frontier.append(parent)
    return closure


def _steps() -> list[str]:
    return [step for steps in _jobs().values() for step in steps]


def _commands(step: str) -> str:
    """A step with its comment lines removed.

    Every check below is about what the runner EXECUTES. Matching prose would
    make a comment mentioning `poetry lock` indistinguishable from running it,
    and a guard that cannot tell those apart is a guard about wording.
    """

    return "\n".join(
        line for line in step.splitlines() if not line.strip().startswith("#")
    )


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


def test_the_workflow_parser_found_the_jobs() -> None:
    """SENSITIVITY for the parser itself: one that returned nothing would make
    every assertion below pass over an empty set."""

    jobs = _jobs()
    assert set(jobs) == {"acquire", "resolve", "attest"}, sorted(jobs)
    for name, steps in jobs.items():
        assert len(steps) >= 4, (name, len(steps))
    assert _needs("attest") == {"resolve", "acquire"}
    assert _needs("acquire") == set()


# ── AMENDMENT 7: the credential and the resolver never share a job ──────────


def test_the_job_that_runs_poetry_references_no_secret() -> None:
    """THE structural repair. Poetry can execute an sdist build backend during
    resolution (GHSA-73h3-mf4w-8647), and while that ran in the credential's
    job the credential was in that code's reach — environment, `.netrc`,
    process tree. No manifest guard closes it, because the executing code is a
    published package's."""

    jobs = _jobs()
    resolver = [
        name
        for name, steps in jobs.items()
        if any("poetry lock" in _commands(step) for step in steps)
    ]
    assert resolver == ["resolve"], resolver
    for step in jobs["resolve"]:
        assert "secrets." not in step, step
    assert "FORGEJO_READ_TOKEN" not in "\n".join(jobs["resolve"])


def test_the_resolver_job_asserts_its_own_emptiness_before_resolving() -> None:
    """A comment is not a property. The job checks that no credential-shaped
    variable and no `.netrc` is present, and it does so before Poetry starts."""

    steps = _jobs()["resolve"]
    assertion = next(
        index for index, step in enumerate(steps) if "no credential is present" in step
    )
    resolution = next(
        index for index, step in enumerate(steps) if "poetry lock" in _commands(step)
    )
    assert assertion < resolution, (assertion, resolution)
    body = steps[assertion]
    assert "POETRY_HTTP_BASIC" in body and ".netrc" in body


def test_the_acquiring_job_runs_no_poetry_and_no_package_code() -> None:
    jobs = _jobs()
    for name in ("acquire", "attest"):
        commands = "\n".join(_commands(step) for step in jobs[name])
        assert "setup-poetry" not in commands, name
        assert not re.search(r"(^|\s)poetry\s", commands), name
        assert "pip install" not in commands, name


def test_there_is_no_authenticated_online_fallback() -> None:
    """The load-bearing clause. A fallback that reaches the index with the
    credential re-creates the exposure the split exists to remove, so there is
    none: the resolver has no credential, the private source points at a local
    bundle, and a package missing from that bundle fails the resolution."""

    commands = "\n".join(_commands(step) for step in _jobs()["resolve"])
    assert "mirror-manifest" in commands
    # No netrc is WRITTEN here — the only mentions are the assertions that one
    # is absent. `machine ... login ... password` is how the acquiring job
    # writes one, and it appears nowhere in this job.
    assert "machine %s login %s password %s" not in commands


# ── AMENDMENT 3: no checkout persists the workflow token ───────────────────


def test_every_checkout_refuses_to_persist_the_token() -> None:
    """`actions/checkout` writes the workflow token into `.git/config` by
    default. On the UNTRUSTED checkout at `work/` that token sits inside a tree
    a resolution may reach, and a git-sourced dependency would use it. It is off
    on the trusted checkout too: nothing here pushes."""

    checkouts = [step for step in _steps() if "actions/checkout@" in step]
    assert len(checkouts) == 5, len(checkouts)
    for step in checkouts:
        assert "persist-credentials: false" in step, step


def test_the_trusted_checkout_comes_first_and_owns_the_workspace_root() -> None:
    """Defect 1. Local actions and scripts resolve from `$GITHUB_WORKSPACE`, so
    whatever is checked out at the root is the code that runs. It must be the
    commit that defines this workflow, never the ref under resolution."""

    for name, steps in _jobs().items():
        checkouts = [step for step in steps if "actions/checkout@" in step]
        assert checkouts, name
        assert "ref: ${{ github.sha }}" in checkouts[0], name
        assert "path:" not in checkouts[0], f"{name}: the trusted checkout owns /"
        for step in checkouts[1:]:
            assert "ref: ${{ inputs.ref }}" in step and "path: work" in step, name


def test_no_local_action_runs_before_the_trusted_checkout() -> None:
    """A `uses: ./...` before the root is populated, or after the untrusted ref
    has been checked out over it, is the original defect returning."""

    steps = _jobs()["resolve"]
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


def test_no_job_holds_the_credential_before_the_tree_is_judged() -> None:
    """The other half of defect 1, now a property of jobs as well as of steps.

    Trusted tooling is necessary and not sufficient: Poetry keys HTTP
    credentials by source NAME, and the ref owns the URL that name points at.
    Nothing may hold the credential until `manifest-guard` has ruled on the
    tree — within a job by step order, across jobs by `needs:`.
    """

    jobs = _jobs()
    guarded = {
        name
        for name, steps in jobs.items()
        if any("manifest-guard" in _commands(step) for step in steps)
    }
    assert guarded, "no job judges the tree at all"
    holders = {
        name
        for name, steps in jobs.items()
        if any("secrets.FORGEJO_READ_TOKEN" in step for step in steps)
    }
    assert holders, "no job holds the credential; this workflow cannot resolve"
    for name in holders:
        steps = jobs[name]
        if name in guarded:
            guard = max(
                index
                for index, step in enumerate(steps)
                if "manifest-guard" in _commands(step)
            )
            held = [
                index
                for index, step in enumerate(steps)
                if "secrets.FORGEJO_READ_TOKEN" in step
            ]
            assert all(index > guard for index in held), (name, guard, held)
        else:
            assert _needs(name) & guarded, name


def test_the_ref_under_resolution_is_only_ever_read_from_work() -> None:
    """Anything the untrusted tree supplies is addressed through `work/`, and
    the scripts that judge it are addressed WITHOUT it."""

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
    """Defect 3's third part. Both inputs are regex-validated in the first job,
    so a direct interpolation was not exploitable — but a sink whose safety
    rests on a check somewhere else is one deleted check away from being a
    sink. They cross as `env:` instead."""

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
    assert len(bodies) >= 10, len(bodies)
    assert any("poetry lock" in body for body in bodies)


def test_no_curl_in_the_workflow_follows_a_redirect() -> None:
    """The redirect policy again, at the other end. `curl_argv` owns the
    transfers that carry the credential; these are the loopback probes, and a
    `-L` here would be a second policy nobody declared."""

    for body in _run_scripts():
        for line in body.splitlines():
            if "curl" not in line:
                continue
            assert " -L" not in line and "--location" not in line, line


def test_no_resolver_log_is_collected_anywhere() -> None:
    """AMENDMENT 4, as a workflow property. The `tee /tmp/resolver.log` and the
    `--resolver-log` argument are both gone; nothing reinstates them quietly."""

    text = WORKFLOW.read_text()
    assert "resolver.log" not in text
    assert "--resolver-log" not in text


def test_the_credential_is_wired_the_way_the_precedent_wires_it() -> None:
    """The identity and the secret are unchanged; the TRANSPORT is not.

    Poetry no longer receives the credential at all — that is the point of the
    split — so `POETRY_HTTP_BASIC_FORGEJO_*` appears exactly once, in the
    resolver job's assertion that it is ABSENT. `ci-reader` now authenticates
    curl in the acquisition job instead.
    """

    text = WORKFLOW.read_text()
    assert '"ci-reader"' in text
    assert "secrets.FORGEJO_READ_TOKEN" in text
    assert "POETRY_HTTP_BASIC_FORGEJO_USERNAME:" not in text
    assert "POETRY_HTTP_BASIC_FORGEJO_PASSWORD:" not in text
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


def test_the_index_url_has_exactly_one_owner() -> None:
    """It moved. The download used to be a `curl` in a `run:` block, which
    meant the URL was declared twice and could drift; it is now
    `kernel_lock.INDEX_URL` and the workflow does not name it at all."""

    assert INDEX_URL not in WORKFLOW.read_text()
    assert INDEX_URL.startswith(ARTIFACT_ORIGIN + "/")


def test_every_action_is_pinned_by_commit() -> None:
    for step in _steps():
        for line in step.splitlines():
            match = re.search(r"uses: (?!\./)(\S+)", line)
            if match:
                assert re.search(r"@[0-9a-f]{40}$", match.group(1)), line


def test_it_is_dispatch_only() -> None:
    text = WORKFLOW.read_text()
    assert "workflow_dispatch:" in text
    for trigger in ("\n  push:", "\n  pull_request:", "\n  schedule:"):
        assert trigger not in text, trigger
