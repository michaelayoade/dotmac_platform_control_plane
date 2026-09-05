"""The refusals `.github/workflows/kernel-lock.yml` needs, out of the YAML.

A lock entry for `dotmac-kernel` is the one part of a pin change that cannot be
written by hand: its two sha256 values are facts about published artifacts. The
workflow that resolves them holds `FORGEJO_READ_TOKEN`, so every check it makes
is a security check, and a security check embedded in a `run:` block is a check
nobody can plant a defect against.

So the checks live here, as functions, and `tests/architecture/
test_kernel_lock_workflow.py` plants a defect against each one. The workflow
runs this module from the TRUSTED checkout — the commit that defines the
workflow — never from the ref under resolution.

## The subjects, deliberately separate

* `set-kernel-version` — move the pin in the manifest, refusing unless exactly
  one declaration matched. Two matches means guessing which one is the pin.
* `manifest-guard` — the ref under resolution supplies the manifest, and
  Poetry keys HTTP credentials by source NAME. A manifest that keeps the name
  `forgejo` and moves its URL would have the credential posted to the new
  host by Poetry itself, with no code execution anywhere. This refuses that,
  refuses every off-index dependency form, refuses a dependency shape it does
  not recognise, and refuses a candidate-supplied `poetry.toml`.
* `acquire` — download the private index's pages and artifacts ONCE, in the
  only job that holds the credential, validating every index-supplied link
  against an approved origin and path prefix, and lay the bytes out as a local
  PEP 503 index. Runs no Poetry and no package code.
* `mirror-manifest` / `restore` — point the manifest at that local index for
  the duration of a SECRET-FREE resolution, then put the real index URL back
  and recompute the lock's `content-hash` with Poetry's own `Locker`, so the
  pair that leaves describes the manifest a consumer will actually apply.
* `wheel-only` — every release the resolution reads metadata for offers a
  parseable wheel, so Poetry's sdist branch — and the PEP 517 build backend at
  the end of it — is unreachable. Run BEFORE `poetry lock` it is a gate; run
  after, a closing observation. A dependency with no usable wheel is named and
  refused, not silently built.
* `verify` — the lock's hashes are the bytes the index published.
* `drift` — the whole lock outside the `dotmac-kernel` entry must be
  identical, and the kernel entry itself may differ only in `version` and
  `files`. Not three fields of it, and not a blank cheque for the one entry
  the change is about.
* `evidence` — assemble what leaves the runner: the manifest/lock PAIR bound
  to each other and to this run, and a scan that refuses rather than passes
  when there is no credential to look for.

## The resolver is wheel-only, and that is checked rather than configured

Splitting the credential out of the resolver job removed the credential from
the build backend's reach. It did not remove the build backend. `resolve` still
reaches public PyPI, so a release with no usable wheel could still have its
sdist backend executed — and the answer to that was a scan for the
CONSEQUENCES of an execution that had already happened.

Preventing the execution is stronger than scanning for its results, so the
resolution is now wheel-only: `wheel_only_problems` refuses any release that
offers no parseable wheel, at three points — while the private bundle is being
laid out, over the pre-resolution lock BEFORE Poetry starts, and over the lock
that leaves. The predicate is not a Poetry flag; it is the exact condition
under which `HTTPRepository._get_info_from_sdist` is unreachable. See that
function's docstring for what it is conservative about and what it does not
cover.

The credential-encoding scans stay exactly where they were, at exactly the
strength they had. They are defence in depth. They were never the defence.

## Nothing scanned-only is uploaded

An earlier version uploaded the resolver log, scrubbed of the credential's
known encodings. The scrubber's own docstring conceded what it could not see —
a credential split across lines, compressed or archived bytes, a hex rendering,
bytes that are not UTF-8, or base64 at a non-zero offset inside a larger blob.
Publishing a file whose scan is known-incomplete is the wrong resolution of
that finding, so the log is no longer collected at all. What remains in the
artifact is the manifest and the lock, and for those the answer to a sighting
is REFUSAL, never redaction: a credential in either of those files means
something is wrong that redaction would hide.

`credential_encodings` therefore exists only to make that refusal possible. Its
coverage limits are unchanged and still do not amount to a proof of absence;
the property the workflow relies on is that the job which produces the lock
never holds the credential at all.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html.parser
import json
import os
import re
import subprocess
import tomllib
import urllib.parse
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

#: The private index this assembly resolves Dotmac packages from. The workflow
#: names the same URL for its own `curl`; a drift between the two is caught by
#: `test_kernel_lock_workflow.py`.
INDEX_URL = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"

#: The ONLY origin an index-supplied link may name, and the only path prefix
#: under it. A simple index page is INDEX-CONTROLLED data: every href on it is
#: attacker-influenced the moment the index is. Validating the origin is what
#: keeps `curl --netrc` from being pointed somewhere the credential would be
#: offered — see `approved_artifact_url`.
ARTIFACT_ORIGIN = "https://registry.dotmac.io"
ARTIFACT_PATH_PREFIX = "/api/packages/dotmac/pypi/"

#: The Poetry source name the credential is keyed to. `POETRY_HTTP_BASIC_
#: FORGEJO_PASSWORD` binds to this NAME, not to the URL, which is the whole
#: reason `manifest_problems` exists.
INDEX_SOURCE_NAME = "forgejo"

#: The read-only Forgejo identity the credential belongs to. Used to build the
#: basic-auth encoding the scan looks for, never to authenticate anything here.
INDEX_USERNAME = "ci-reader"

#: The environment variable the workflow hands the credential to this module
#: in. Deliberately not named `TOKEN`: nothing here may ever accept it as a
#: command-line argument, where it would appear in a process listing.
CREDENTIAL_ENV = "FORGEJO_CREDENTIAL"

#: The package this workflow exists to move. Everything else in the lock is
#: required to be identical.
KERNEL = "dotmac-kernel"

#: The only two fields of the `dotmac-kernel` entry a pin move may change.
#: Everything else on that entry — `source`, `dependencies`, `extras`,
#: `optional`, `groups`, `python-versions`, `description`, anything new — is
#: held to the same identity as every other package. The gate this replaced
#: exempted the whole entry, so a repointed kernel source, a widened
#: `python-versions` or an added dependency arrived inside the one entry the
#: change was about and nothing looked.
KERNEL_MUTABLE_FIELDS = frozenset({"version", "files"})

#: The two files a consumer must apply TOGETHER. The lock's content-hash is
#: derived from the manifest, so either one alone describes a tree that does
#: not exist.
PAIR = ("pyproject.toml", "poetry.lock")

#: Poetry configuration a candidate checkout may not carry. `poetry.toml` is
#: read from the project directory and configures the resolver that is about to
#: run against it — `certificates.<source>.cert = false` turns off TLS
#: verification for a named repository, `keyring.enabled` changes where
#: credentials come from, and `solver.lazy-wheel` changes how a wheel's
#: metadata is obtained. This module REFUSES the file rather than reasoning
#: about which keys are safe: an allowlist of settings is a second thing to
#: keep in sync with Poetry, and the tree under resolution has no legitimate
#: need to configure the tool that judges it.
#:
#: NOT for the reason an earlier revision of this comment gave. It claimed
#: `installer.no-binary` "forces source distributions and therefore
#: build-backend execution". That is false of the command this workflow runs.
#: In the pinned Poetry (2.4.1) `installer.no-binary` and `installer.only-binary`
#: are read in exactly one place — `poetry/installation/chooser.py` — which is
#: the INSTALLER's link chooser. `poetry lock` never constructs one. Neither
#: setting can make `poetry lock` execute a build backend, and neither can stop
#: it: what decides that is whether a release offers a parseable wheel, which
#: is what `wheel_only_problems` below judges. Refusing the file is still
#: right; the reason is TLS, keyring and metadata transport, not no-binary.
CANDIDATE_CONFIG_FILES = ("poetry.toml",)

_KERNEL_DECLARATION = re.compile(r'(dotmac-kernel = \{ version = ")[^"]+(")')

_CONTENT_HASH_LINE = re.compile(r'^(content-hash = ")[^"]*(")$', re.MULTILINE)

#: Constraint-table keys `poetry.core.factory.Factory.create_dependency`
#: actually reads. The traversal below enumerates what it understands and
#: refuses what it does not, rather than allowing anything that fails to match
#: a known-bad pattern: an omitted form is otherwise waved through in silence,
#: which is exactly how `file` — a distinct key from `path`, dispatched three
#: branches earlier in that same function — was missed.
RECOGNISED_CONSTRAINT_KEYS = frozenset(
    {
        "allow-prereleases",
        "branch",
        "develop",
        "extras",
        "file",
        "git",
        "markers",
        "optional",
        "path",
        "platform",
        "python",
        "rev",
        "source",
        "subdirectory",
        "tag",
        "url",
        "version",
    }
)

#: Dependency forms whose resolution reads or executes something the index does
#: not name. `path` and `url` and `file` reach outside the index; `git` clones
#: and can run a build backend from the cloned tree.
OFF_INDEX_DEPENDENCY_KEYS = ("file", "git", "path", "url")

#: Every dotted path this module TRAVERSES for dependencies. A `dependenc`-named
#: table anywhere else in the manifest is a form that did not exist when this
#: was written, and it is refused rather than ignored.
TRAVERSED_DEPENDENCY_TABLES = (
    "dependency-groups",
    "project.dependencies",
    "project.optional-dependencies",
    "tool.poetry.dependencies",
    "tool.poetry.dev-dependencies",
)

#: `tool.poetry.group.<name>` may carry these and nothing else.
RECOGNISED_GROUP_KEYS = frozenset({"dependencies", "include-groups", "optional"})

#: A bare `name = "<constraint>"` in a Poetry table is a VERSION constraint and
#: nothing else. Anything carrying a scheme, an authority or a direct reference
#: is not a version constraint, and is refused instead of being parsed.
_PLAIN_CONSTRAINT = re.compile(r"^[0-9A-Za-z .,!*+<>=^~|-]+$")

#: An exact pin: what a mirrored private package must declare, because the
#: bundle can only be CLOSED around versions known before resolution starts.
_EXACT_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*((a|b|rc|\.post|\.dev)[0-9]+)?$")

#: A PEP 508 direct reference — `name @ https://…`, `name @ file:///…`,
#: `name @ git+ssh://…`. In `[project]` and `[dependency-groups]` a dependency
#: is a string, so the off-index forms above arrive as one of these.
_DIRECT_REFERENCE = re.compile(r"@\s*[A-Za-z][A-Za-z0-9+.-]*:")

_PAIR_PROSE = """\
This lock and this pyproject.toml are ONE artifact. The lock's content-hash is
derived from the manifest, so applying either alone leaves a tree whose lock
does not describe its own manifest.

To verify what you downloaded, from inside the artifact directory:

  sha256sum -c SHA256SUMS

To verify the pair is the pair this run produced, and not two files from two
runs: recompute pair-binding as the sha256 of exactly these bytes, newline
terminated, in this order:

  pyproject.toml sha256:<the pyproject.toml digest above>
  poetry.lock sha256:<the poetry.lock digest above>

To verify the pair against Poetry itself, copy BOTH files over a checkout of
the ref above and run `poetry check --lock`. Applying one without the other
fails that command on the content-hash, which is the detection this binding
exists to make possible.

The resolver log is deliberately NOT here. It was uploaded once, scrubbed of
the credential's known encodings, and the scrubber could not see a credential
split across lines, compressed, hex-rendered, or base64-encoded at a non-zero
offset. A file whose scan is known-incomplete does not become safe by being
scanned, so it is no longer collected. The lock in this directory was produced
by a job that never held the credential at all.

This artifact is bound to its run by the coordinates above, which the run's own
log carries. It is not cryptographically signed: attesting it would need
`id-token: write` and `attestations: write`, a permission expansion this
workflow has not taken.
"""


class Refusal(Exception):
    """A condition this module refuses to proceed past."""


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


# ── set-kernel-version ──────────────────────────────────────────────────────


def replace_kernel_version(text: str, version: str) -> str:
    """Move the pin, or refuse.

    Exactly one declaration, because a manifest with two is a manifest where
    "the pin" is ambiguous, and editing the wrong one produces a lock that
    resolves a version nobody asked for while reporting success.
    """

    edited, count = _KERNEL_DECLARATION.subn(rf"\g<1>{version}\g<2>", text)
    if count != 1:
        raise Refusal(
            f"expected exactly one {KERNEL} version declaration, matched "
            f"{count}. Refusing rather than guessing which one the pin is."
        )
    return edited


# ── manifest-guard: the candidate checkout ──────────────────────────────────


def checkout_problems(root: Path) -> list[str]:
    """A candidate checkout may supply the manifest. It may not supply config.

    `poetry.toml` in the project directory is Poetry's LOCAL configuration
    file, and it is read by the resolver that is about to run against this
    tree. It can disable TLS verification for a named repository, force source
    distributions (and so build-backend execution), and change where
    credentials are looked up. We do not assume Poetry ignores it and we do not
    allowlist "safe" keys: the file is refused.
    """

    problems: list[str] = []
    for name in CANDIDATE_CONFIG_FILES:
        if (root / name).exists():
            problems.append(
                f"the checkout under resolution carries `{name}`; that file "
                "configures the Poetry that is about to resolve it — TLS "
                "verification, binary-vs-source preference and credential "
                "lookup are all settable there. The ref supplies the manifest, "
                "never the configuration."
            )
    return problems


# ── manifest-guard: the dependency traversal ────────────────────────────────


def _walk_keys(node: Any, prefix: str = "") -> Iterator[str]:
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        yield path
        yield from _walk_keys(value, path)


def _is_traversed(path: str) -> bool:
    if path in TRAVERSED_DEPENDENCY_TABLES:
        return True
    parts = path.split(".")
    if parts[:3] == ["tool", "poetry", "group"] and len(parts) == 5:
        return parts[4] == "dependencies"
    # Keys *inside* a table we traverse are dependency names, not tables.
    return any(
        path.startswith(f"{table}.") for table in TRAVERSED_DEPENDENCY_TABLES
    ) or (parts[:3] == ["tool", "poetry", "group"] and len(parts) > 5)


def unrecognised_dependency_tables(manifest: dict[str, Any]) -> list[str]:
    """Every `dependenc`-named table this module does not traverse.

    The point is the NEXT form, not the current ones. Poetry has grown
    `[tool.poetry.dev-dependencies]`, `[tool.poetry.group.<g>.dependencies]`,
    PEP 621 `[project.dependencies]` / `[project.optional-dependencies]` and
    PEP 735 `[dependency-groups]`, each at a different path; a guard that
    enumerates only the paths it happened to know about lets the next one
    through in silence. This one refuses a path it does not recognise.
    """

    problems: list[str] = []
    for path in _walk_keys(manifest):
        if "dependenc" not in path.rsplit(".", 1)[-1]:
            continue
        if _is_traversed(path):
            continue
        problems.append(
            f"`{path}` names dependencies and is not a form this guard "
            "traverses. Refusing rather than resolving something unexamined — "
            "add it to TRAVERSED_DEPENDENCY_TABLES with a plant beside it."
        )
    return problems


def _constraint_problems(where: str, spec: Any) -> list[str]:
    """One Poetry constraint: a string, a table, or a list of tables."""

    problems: list[str] = []
    if isinstance(spec, list):
        for index, item in enumerate(spec):
            # Multiple constraints for one name. Poetry resolves EVERY entry,
            # so a list is exactly as good a place to hide a `git` or `url`
            # dependency as a bare table — and a traversal that only looked at
            # tables walked straight past it.
            problems += _constraint_problems(f"{where}[{index}]", item)
        return problems
    if isinstance(spec, str):
        if not _PLAIN_CONSTRAINT.fullmatch(spec):
            problems.append(
                f"{where} is the constraint {spec!r}, which is not a plain "
                "version constraint; a bare Poetry constraint may not carry a "
                "scheme, an authority or a direct reference"
            )
        return problems
    if not isinstance(spec, dict):
        problems.append(
            f"{where} is a {type(spec).__name__}, which is not a dependency "
            "shape this guard recognises"
        )
        return problems

    for key in sorted(set(spec) - RECOGNISED_CONSTRAINT_KEYS):
        problems.append(
            f"{where} carries the unrecognised key `{key}`; this guard refuses "
            "a dependency form it does not understand rather than assuming it "
            "is harmless"
        )
    for key in OFF_INDEX_DEPENDENCY_KEYS:
        if key in spec:
            problems.append(
                f"{where} is a `{key}` dependency; resolving it reads or "
                "executes something the index does not name"
            )
    source = spec.get("source")
    if source is not None and source != INDEX_SOURCE_NAME:
        problems.append(
            f"{where} resolves from source {source!r}, which this job does not "
            "hold a credential for"
        )
    return problems


def _requirement_problems(where: str, requirement: Any) -> list[str]:
    """One PEP 508 requirement string, as `[project]` and PEP 735 carry them."""

    if isinstance(requirement, dict):
        if set(requirement) == {"include-group"}:
            return []
        return [
            f"{where} is a table with keys {sorted(requirement)}; the only "
            "table PEP 735 defines here is `include-group`"
        ]
    if not isinstance(requirement, str):
        return [
            f"{where} is a {type(requirement).__name__}, not a PEP 508 "
            "requirement string"
        ]
    if _DIRECT_REFERENCE.search(requirement) or "://" in requirement:
        return [
            f"{where} is the direct reference {requirement!r}; a PEP 508 URL "
            "reaches outside the index exactly as a `url`, `file`, `path` or "
            "`git` table does"
        ]
    return []


def _poetry_constraint_tables(
    manifest: dict[str, Any],
) -> list[tuple[str, dict[str, Any]]]:
    poetry = manifest.get("tool", {}).get("poetry", {})
    if not isinstance(poetry, dict):
        return []
    tables: list[tuple[str, dict[str, Any]]] = []
    for key in ("dependencies", "dev-dependencies"):
        table = poetry.get(key)
        if isinstance(table, dict):
            tables.append((f"tool.poetry.{key}", table))
    groups = poetry.get("group", {})
    if isinstance(groups, dict):
        for name, group in sorted(groups.items()):
            if not isinstance(group, dict):
                continue
            deps = group.get("dependencies")
            if isinstance(deps, dict):
                tables.append((f"tool.poetry.group.{name}.dependencies", deps))
    return tables


def _group_shape_problems(manifest: dict[str, Any]) -> list[str]:
    poetry = manifest.get("tool", {}).get("poetry", {})
    groups = poetry.get("group", {}) if isinstance(poetry, dict) else {}
    problems: list[str] = []
    if not isinstance(groups, dict):
        return problems
    for name, group in sorted(groups.items()):
        if not isinstance(group, dict):
            problems.append(f"tool.poetry.group.{name} is not a table")
            continue
        for key in sorted(set(group) - RECOGNISED_GROUP_KEYS):
            problems.append(
                f"tool.poetry.group.{name} carries the unrecognised key "
                f"`{key}`; a group form this guard does not understand is "
                "refused, not resolved"
            )
    return problems


def dependency_problems(manifest: dict[str, Any]) -> list[str]:
    """Every dependency, in every form Poetry accepts, judged."""

    problems = unrecognised_dependency_tables(manifest)
    problems += _group_shape_problems(manifest)

    for table, deps in _poetry_constraint_tables(manifest):
        for name, spec in sorted(deps.items()):
            problems += _constraint_problems(f"{table}.{name}", spec)

    project = manifest.get("project", {})
    if isinstance(project, dict):
        listed = project.get("dependencies")
        if isinstance(listed, list):
            for index, requirement in enumerate(listed):
                problems += _requirement_problems(
                    f"project.dependencies[{index}]", requirement
                )
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra, requirements in sorted(optional.items()):
                if not isinstance(requirements, list):
                    problems.append(
                        f"project.optional-dependencies.{extra} is not a list"
                    )
                    continue
                for index, requirement in enumerate(requirements):
                    problems += _requirement_problems(
                        f"project.optional-dependencies.{extra}[{index}]",
                        requirement,
                    )

    pep735 = manifest.get("dependency-groups", {})
    if isinstance(pep735, dict):
        for group, requirements in sorted(pep735.items()):
            if not isinstance(requirements, list):
                problems.append(f"dependency-groups.{group} is not a list")
                continue
            for index, requirement in enumerate(requirements):
                problems += _requirement_problems(
                    f"dependency-groups.{group}[{index}]", requirement
                )
    return problems


def _kernel_declaration(manifest: dict[str, Any]) -> Any:
    for _table, deps in _poetry_constraint_tables(manifest):
        if KERNEL in deps:
            return deps[KERNEL]
    return None


def manifest_problems(manifest: dict[str, Any], kernel_version: str) -> list[str]:
    """Everything about this manifest that would misdirect the credential.

    The threat is not only code execution. Poetry resolves `POETRY_HTTP_BASIC_
    FORGEJO_PASSWORD` by the source NAME `forgejo`, and the ref under
    resolution owns the URL that name points at. Changing the URL and keeping
    the name is enough to have Poetry send the credential to another host, with
    nothing untrusted ever executing.

    PREMISE, and it is now enforced rather than asserted: this assembly uses
    the legacy `[tool.poetry]` layout. A ref that ADDED a PEP 621 `[project]`
    table alongside it — the documented enrichment shape, where
    `project.dependencies` supplies dependencies and `tool.poetry.dependencies`
    only annotates them — used to be unexamined, because the traversal read
    `tool.poetry` and nothing else. `dependency_problems` reads every form.
    """

    problems: list[str] = []
    sources = manifest.get("tool", {}).get("poetry", {}).get("source", [])
    if not isinstance(sources, list):
        sources = []

    named = [entry for entry in sources if entry.get("name") == INDEX_SOURCE_NAME]
    if len(named) != 1:
        problems.append(
            f"expected exactly one `[[tool.poetry.source]]` named "
            f"{INDEX_SOURCE_NAME!r}, found {len(named)}"
        )
    for entry in named:
        url = str(entry.get("url", ""))
        if url != INDEX_URL:
            problems.append(
                f"source {INDEX_SOURCE_NAME!r} points at {url!r}, not "
                f"{INDEX_URL!r} — the credential is keyed to the NAME, so this "
                "would send it to that host"
            )
    for entry in sources:
        name = str(entry.get("name", "?"))
        if name == INDEX_SOURCE_NAME:
            continue
        problems.append(
            f"unexpected `[[tool.poetry.source]]` {name!r} at "
            f"{entry.get('url', '?')!r}; this job resolves against one index"
        )

    problems += dependency_problems(manifest)

    if "requires-plugins" in manifest.get("tool", {}).get("poetry", {}):
        problems.append(
            "`tool.poetry.requires-plugins` is declared; Poetry installs and "
            "imports plugins before it resolves, which is arbitrary code in "
            "the step that holds the credential"
        )

    kernel = _kernel_declaration(manifest)
    if kernel is None:
        problems.append(f"no {KERNEL} dependency to resolve")
    elif isinstance(kernel, dict):
        if kernel.get("version") != kernel_version:
            problems.append(
                f"{KERNEL} declares {kernel.get('version')!r} after the edit, "
                f"asked for {kernel_version!r}"
            )
        if kernel.get("source") != INDEX_SOURCE_NAME:
            problems.append(
                f"{KERNEL} resolves from {kernel.get('source')!r}, not "
                f"{INDEX_SOURCE_NAME!r}"
            )
    else:
        problems.append(
            f"{KERNEL} is declared as a bare constraint, so nothing binds it "
            f"to the {INDEX_SOURCE_NAME!r} index"
        )
    return problems


# ── the index is data: every link it supplies is validated ──────────────────


class _Links(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value:
                self.hrefs.append(value)


def index_links(page: str) -> list[str]:
    parser = _Links()
    parser.feed(page)
    return parser.hrefs


def approved_artifact_url(href: str, page_url: str) -> str:
    """Resolve an index-supplied href, or refuse it.

    A simple index page is data the INDEX controls, and `curl --netrc` offers
    the credential to whatever host it is pointed at whose name appears in the
    netrc file. So the destination is validated before the transfer, not after:
    exactly `https`, exactly the approved authority, under exactly the approved
    path prefix, with no userinfo and no traversal segment.

    A RELATIVE href is normal on a simple index, so `..` is resolved rather
    than refused on sight — and then the RESOLVED path is required to be under
    the approved prefix, which is what a traversal chain fails. Refusing the
    raw `..` instead would have refused a legitimate index page while proving
    nothing extra.

    REDIRECT POLICY: redirects are not followed at all — see `curl_argv`, which
    carries no `--location`, and `transfer_problems`, which refuses any status
    but 200. There is therefore no second hop to re-validate. This function is
    still the validator a hop would have to pass, and the test suite drives it
    with a redirect target to say so.
    """

    if not href.strip():
        raise Refusal("the index page carries an empty href")
    resolved = urllib.parse.urljoin(page_url, href.split("#", 1)[0])
    parts = urllib.parse.urlsplit(resolved)
    if parts.scheme != "https":
        raise Refusal(
            f"index link {href!r} resolves to {parts.scheme or '(none)'}://, "
            "not https; the credential is never offered over a scheme that "
            "does not authenticate the server"
        )
    if "@" in parts.netloc:
        raise Refusal(
            f"index link {href!r} carries userinfo in its authority, which is "
            "both a credential and a host-spoofing surface"
        )
    approved = urllib.parse.urlsplit(ARTIFACT_ORIGIN)
    authority = approved.netloc.lower()
    if parts.netloc.lower() not in {authority, f"{authority}:443"}:
        raise Refusal(
            f"index link {href!r} resolves to origin {parts.netloc!r}, not "
            f"{approved.netloc!r}; refusing to point an authenticated transfer "
            "at a host the index chose"
        )
    if ".." in parts.path.split("/"):
        raise Refusal(f"index link {href!r} still traverses after resolution")
    if not parts.path.startswith(ARTIFACT_PATH_PREFIX):
        raise Refusal(
            f"index link {href!r} resolves to path {parts.path!r}, which is "
            f"not under {ARTIFACT_PATH_PREFIX!r} — a `..` chain that walks out "
            "of the package directory lands here"
        )
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def curl_argv(url: str, target: Path) -> list[str]:
    """The transfer, stated once.

    No `--location`. `--proto '=https'` means the transfer will not begin over
    any other scheme even if something upstream rewrote the URL, and
    `--max-redirs 0` declares the same intention a second way. `-w` makes the
    status code observable so a 3xx cannot be mistaken for a download.
    """

    return [
        "curl",
        "--netrc",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--silent",
        "--show-error",
        "-w",
        "%{http_code}",
        "-o",
        str(target),
        url,
    ]


def transfer_problems(url: str, status: str) -> list[str]:
    """Anything but a 200 refuses, and a 3xx says why in its own words."""

    if status == "200":
        return []
    if status.startswith("3"):
        return [
            f"{url} answered {status}: a redirect. Redirects are NOT followed "
            "here — a followed redirect is a second destination the index "
            "chose, and `curl --netrc` would offer the credential to it if its "
            "host matched the netrc entry. Refusing."
        ]
    return [f"{url} answered {status}, not 200"]


def fetch(url: str, target: Path) -> None:
    """Download `url` to `target`, or refuse. Never follows a redirect."""

    target.parent.mkdir(parents=True, exist_ok=True)
    # S603: the argument vector is built by `curl_argv` from a fixed list, and
    # `url` has already been through `approved_artifact_url` — https, the
    # approved authority, under the approved path prefix. No shell is involved.
    completed = subprocess.run(  # noqa: S603
        curl_argv(url, target),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise Refusal(f"curl failed for {url}: {completed.stderr.strip()}")
    problems = transfer_problems(url, completed.stdout.strip())
    if problems:
        raise Refusal(problems[0])


# ── acquire: a closed bundle, downloaded once, by the only job with a key ───


def _normalised(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def artifact_belongs_to(filename: str, package: str, version: str) -> bool:
    prefix = f"{_normalised(package)}-{version}"
    stem = _normalised(filename.split("-")[0]) if "-" in filename else ""
    if stem and stem != _normalised(package):
        return False
    return filename.lower().startswith(prefix.lower()) and (
        filename[len(prefix) : len(prefix) + 1] in {"-", "."}
    )


def acquisition_plan(
    manifest: dict[str, Any], lock: dict[str, Any], kernel_version: str
) -> dict[str, str]:
    """Which private packages the bundle must CLOSE over, and at which version.

    The bundle is the resolver's only view of the private index, so it has to
    be closed before resolution starts. It is closed the only way it can be:
    every package the manifest binds to the private source, at the exact
    version the manifest pins, plus every package the PRE-resolution lock
    already resolved from that source (a transitive private dependency the
    manifest never names), plus `dotmac-kernel` at the version being moved to.

    A private dependency that is not an EXACT pin is refused. A range cannot be
    mirrored without deciding what it resolves to, and deciding that here would
    be this module inventing the answer the resolver exists to produce.
    """

    plan: dict[str, str] = {}
    for table, deps in _poetry_constraint_tables(manifest):
        for name, spec in sorted(deps.items()):
            if not isinstance(spec, dict):
                continue
            if spec.get("source") != INDEX_SOURCE_NAME:
                continue
            version = spec.get("version")
            if not isinstance(version, str) or not _EXACT_VERSION.fullmatch(version):
                raise Refusal(
                    f"{table}.{name} resolves from {INDEX_SOURCE_NAME!r} with "
                    f"the constraint {version!r}. The offline bundle can only "
                    "be closed around exact pins; a range would need this "
                    "module to decide what it resolves to."
                )
            plan[name] = version

    for entry in lock.get("package", []):
        source = entry.get("source", {})
        if not isinstance(source, dict):
            continue
        if source.get("reference") != INDEX_SOURCE_NAME:
            continue
        name = str(entry.get("name"))
        plan.setdefault(name, str(entry.get("version")))

    if KERNEL not in plan:
        raise Refusal(f"no {KERNEL} dependency bound to {INDEX_SOURCE_NAME!r}")
    plan[KERNEL] = kernel_version
    return plan


def kernel_artifact_names(version: str) -> set[str]:
    return {
        f"dotmac_kernel-{version}-py3-none-any.whl",
        f"dotmac_kernel-{version}.tar.gz",
    }


# ── wheel-only: the resolver is never handed something it must build ────────

#: A wheel filename as POETRY parses one. This is `poetry.utils.patterns
#: .wheel_file_re` from 2.4.1 — the version `.github/bootstrap/
#: poetry-requirements.txt` pins — copied deliberately rather than imported,
#: because this module runs in `acquire`, a job that installs no Poetry at all.
#:
#: NOT `endswith(".whl")`. `HTTPRepository._get_info_from_links` sorts links
#: into wheels and sdists by extension, but then reads each wheel with THIS
#: pattern and `continue`s past any filename it cannot parse. A release whose
#: only ".whl" files are unparseable therefore leaves all four wheel slots
#: empty and falls through to the sdist branch exactly as if it had offered no
#: wheel at all — so a check on the extension would admit precisely the case
#: that still builds.
_WHEEL_FILENAME = re.compile(
    r"^(?P<namever>(?P<name>.+?)-(?P<ver>\d[^-]*))"
    r"(-(?P<build>\d[^-]*))?"
    r"-(?P<pyver>[^-]+)"
    r"-(?P<abi>[^-]+)"
    r"-(?P<plat>[^-]+)"
    r"\.whl$"
)


def parseable_wheels(filenames: Iterable[str]) -> list[str]:
    """The subset of these filenames Poetry would accept as a metadata source."""

    return sorted(name for name in filenames if _WHEEL_FILENAME.match(name))


def wheel_only_problems(
    offers: Iterable[tuple[str, str, Iterable[str]]],
) -> list[str]:
    """Every release here offers a wheel, so no build backend can run.

    THE MECHANISM, stated as the condition it actually is. Poetry decides where
    a release's metadata comes from in `HTTPRepository._get_info_from_links`:
    if the release offers at least one parseable wheel it returns from a wheel
    branch, always, and `_get_info_from_sdist` is unreachable. Only when no
    parseable wheel is present does it reach
    `_get_info_from_metadata(sdists[0]) or _get_info_from_sdist(sdists[0])`,
    and `_get_info_from_sdist` is `PackageInfo.from_sdist`, which unpacks the
    archive and — when its PKG-INFO carries no `Requires-Dist` — calls
    `get_pep517_metadata`, which runs the project's own build backend in a
    subprocess. That is arbitrary published code executing inside the resolver.

    So "a wheel is offered" is not a preference or a flag. It is the exact
    predicate under which that code path cannot be taken, and this refuses
    every release that fails it, BY NAME, rather than letting the resolver
    discover the answer by running the thing.

    There is no Poetry setting that does this. `installer.no-binary` and
    `installer.only-binary` are the INSTALLER's link chooser and have no
    bearing on `poetry lock` — see `CANDIDATE_CONFIG_FILES`.

    WHAT THIS IS CONSERVATIVE ABOUT, and it errs towards refusing:

    * A sdist-only release whose index serves PEP 658 core metadata would be
      read by `_get_info_from_metadata` without any build. This refuses it
      anyway. Admitting it would mean trusting an index-supplied `.metadata`
      link to exist at resolution time, which is a promise about a remote
      server, not a fact about these files.

    WHAT IT DOES NOT COVER, which is a smaller set but not empty:

    * A YANKED wheel. `_get_info_from_links` drops yanked links before it
      classifies them, and a lock's `files` list does not record yanked state.
      A release whose only wheel is yanked passes this and still builds. The
      answer is not available from the artifacts this workflow holds.
    * A candidate VERSION the solver considers and discards. Metadata is
      fetched for candidates that never reach a lock, and no check over the
      locks before and after can see one. That region is unmonitored, not
      covered — `drift_problems` refuses any package that appears or
      disappears, so the SET is pinned, but the versions explored inside it
      are not.
    """

    problems: list[str] = []
    for name, version, filenames in offers:
        files = sorted(filenames)
        if not files:
            problems.append(
                f"{name} {version} offers no published files at all. Nothing "
                "here can say where its metadata would come from, and a "
                "release with no files is not an index release — it is a "
                "directory, a git clone or a URL, every one of which resolves "
                "by running a build backend."
            )
        elif not parseable_wheels(files):
            problems.append(
                f"{name} {version} offers {files} and not one usable wheel "
                "among them. Resolution would have to take its metadata from "
                "the source distribution, which unpacks the archive and, when "
                "PKG-INFO carries no `Requires-Dist`, EXECUTES that project's "
                "PEP 517 build backend inside this job. A dependency with no "
                "usable wheel is refused; there is no fallback that builds it."
            )
    return problems


def lock_wheel_problems(lock: dict[str, Any]) -> list[str]:
    """`wheel_only_problems` over every package a lock names.

    Run on the PRE-resolution lock this is a gate: it refuses before Poetry
    starts, which is the only position from which refusing prevents anything.
    Run again on the produced lock it is the closing observation, and together
    with `drift_problems` — which refuses any package that appeared or
    disappeared — the two describe the same set of packages.
    """

    return wheel_only_problems(
        (
            str(entry.get("name")),
            str(entry.get("version")),
            [str(item.get("file")) for item in entry.get("files", [])],
        )
        for entry in lock.get("package", [])
    )


def acquire(plan: dict[str, str], out: Path) -> dict[str, str]:
    """Download the closed bundle and lay it out as a local PEP 503 index.

    Runs in the ONLY job that holds the credential, and runs no Poetry and no
    package code: `curl`, `sha256`, and writing HTML. Returns filename → digest.
    """

    files_dir = out / "files"
    simple_dir = out / "simple"
    files_dir.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}

    for package, version in sorted(plan.items()):
        page = out / "pages" / f"{package}.html"
        fetch(f"{INDEX_URL}/{package}/", page)
        wanted: dict[str, str] = {}
        for href in index_links(page.read_text(encoding="utf-8", errors="replace")):
            url = approved_artifact_url(href, f"{INDEX_URL}/{package}/")
            filename = url.rsplit("/", 1)[-1]
            if artifact_belongs_to(filename, package, version):
                wanted[filename] = url
        if not wanted:
            raise Refusal(
                f"{package} {version} is not published on the index. This is a "
                "refusal in its own right: a resolver error later would report "
                "it as a lock problem rather than as 'it was never published', "
                "which is the fact that matters."
            )
        offered = wheel_only_problems([(package, version, list(wanted))])
        if offered:
            # THE SDIST IS STILL ACQUIRED AND STILL HASHED. What this refuses
            # is a private release that offers the resolver NOTHING BUT an
            # sdist — because the mirror page written below is the resolver's
            # whole view of this package, and a page with no wheel on it is a
            # build. A page carrying both is not: the wheel's presence is what
            # makes the sdist unreachable as a metadata source, which is why
            # both links stay and the lock keeps both hashes.
            raise Refusal(offered[0])
        if package == KERNEL:
            expected = kernel_artifact_names(version)
            if set(wanted) != expected:
                raise Refusal(
                    f"the index publishes {sorted(wanted)} for {KERNEL} "
                    f"{version}; this workflow pins the pair {sorted(expected)}"
                )
        for filename, url in sorted(wanted.items()):
            target = files_dir / filename
            fetch(url, target)
            digests[filename] = sha256_hex(target.read_bytes())

        page_dir = simple_dir / package
        page_dir.mkdir(parents=True, exist_ok=True)
        rows = "\n".join(
            f'    <a href="../../files/{name}#sha256={digests[name]}">{name}</a><br>'
            for name in sorted(wanted)
        )
        page_dir.joinpath("index.html").write_text(
            f"<!DOCTYPE html>\n<html><body>\n{rows}\n</body></html>\n",
            encoding="utf-8",
        )

    (out / "digests.json").write_text(
        json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return digests


# ── the mirror swap, and putting the real URL back ──────────────────────────


def point_at_mirror(manifest_text: str, mirror_url: str) -> str:
    """Aim the private source at the local bundle for a SECRET-FREE resolve.

    The private index needs a credential, so a resolver job that holds none
    cannot reach it — the bundle is not an optimisation, it is the only way the
    split exists. `manifest-guard` has already proven the source URL is the
    real index before this runs, so what is being replaced is known.
    """

    if manifest_text.count(INDEX_URL) != 1:
        raise Refusal(
            f"expected exactly one {INDEX_URL!r} in the manifest, found "
            f"{manifest_text.count(INDEX_URL)}"
        )
    return manifest_text.replace(INDEX_URL, mirror_url)


def restore_index_url(text: str, mirror_url: str, *, required: bool = True) -> str:
    """Put the real index URL back wherever the mirror URL reached.

    The manifest that leaves must be the manifest a consumer applies, and the
    lock's `[package.source]` entries must name the index the packages actually
    came from. The mirror URL is an implementation detail of one job and must
    not survive into the artifact.
    """

    if required and mirror_url not in text:
        raise Refusal(f"{mirror_url!r} does not appear; nothing to restore")
    return text.replace(mirror_url, INDEX_URL)


def set_content_hash(lock_text: str, digest: str) -> str:
    edited, count = _CONTENT_HASH_LINE.subn(rf"\g<1>{digest}\g<2>", lock_text)
    if count != 1:
        raise Refusal(
            f"expected exactly one `content-hash` line in the lock, matched " f"{count}"
        )
    return edited


def poetry_content_hash(manifest: Path, lock: Path) -> str:
    """Poetry's OWN content hash for a manifest, computed offline.

    Restoring the source URL changes the manifest, and `source` is one of the
    keys Poetry's `Locker` hashes — so the hash the offline resolution wrote
    describes the mirror manifest, not the one that leaves. This asks Poetry's
    own implementation for the right value rather than re-implementing an
    algorithm that would then be free to drift from it.

    It is a private attribute, so it is checked rather than trusted, and the
    workflow runs `poetry check --lock` immediately afterwards — that command
    is offline, is Poetry's own answer to "does this lock describe this
    manifest", and is what actually proves this step.
    """

    try:
        from poetry.packages.locker import Locker
    except ImportError as error:  # pragma: no cover - environment-dependent
        raise Refusal(
            "Poetry is not importable, so its content hash cannot be asked "
            f"for: {error}"
        ) from error
    locker = Locker(lock, _load_toml(manifest))
    digest = getattr(locker, "_content_hash", None)
    if not isinstance(digest, str) or not digest:
        raise Refusal(
            "Poetry's Locker did not yield a content hash; its internals have "
            "moved and this step must be rewritten against the new shape "
            "rather than guessed at"
        )
    return digest


# ── verify: the lock's hashes are the index's bytes ─────────────────────────


def hash_problems(
    lock: dict[str, Any], digests: dict[str, str], kernel_version: str
) -> list[str]:
    """Every private entry's files, against the bytes that were downloaded.

    The bytes came off the index in the acquisition job, were hashed there, and
    travelled to the resolver as files. Comparing the lock with the index's own
    ADVERTISED hashes would compare the index with itself; this compares the
    lock with what those bytes actually hash to.
    """

    problems: list[str] = []
    kernel = [e for e in lock.get("package", []) if e.get("name") == KERNEL]
    if len(kernel) != 1:
        return [f"the lock carries {len(kernel)} {KERNEL} entries, expected one"]
    if kernel[0].get("version") != kernel_version:
        problems.append(
            f"lock resolved {kernel[0].get('version')!r}, asked for "
            f"{kernel_version!r}"
        )
    expected = kernel_artifact_names(kernel_version)
    locked = {f["file"]: f["hash"] for f in kernel[0].get("files", [])}
    if set(locked) != expected:
        problems.append(
            f"the {KERNEL} entry names {sorted(locked)}; the pair this "
            f"workflow verifies is {sorted(expected)}"
        )

    for entry in lock.get("package", []):
        source = entry.get("source", {})
        if not isinstance(source, dict):
            continue
        if source.get("reference") != INDEX_SOURCE_NAME:
            continue
        for item in entry.get("files", []):
            name, digest = item.get("file"), item.get("hash")
            if name not in digests:
                problems.append(
                    f"{entry.get('name')}: the lock names {name!r}, which is "
                    "not a file this run downloaded from the index"
                )
                continue
            if digest != f"sha256:{digests[name]}":
                problems.append(
                    f"{name}: lock says {digest!r}, the published bytes hash "
                    f"to sha256:{digests[name]}"
                )
    return problems


# ── drift ───────────────────────────────────────────────────────────────────


def _entries(lock: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in lock.get("package", []):
        key = (str(entry.get("name")), str(entry.get("version")))
        if key in found:
            raise Refusal(f"the lock carries two entries for {key}")
        found[key] = entry
    if not found:
        raise Refusal("the lock has no packages at all")
    return found


def _changed_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(
        field
        for field in set(before) | set(after)
        if before.get(field) != after.get(field)
    )


def _kernel_entry_problems(
    old: dict[tuple[str, str], dict[str, Any]],
    new: dict[tuple[str, str], dict[str, Any]],
) -> list[str]:
    """The kernel entry may move its version and its files. Nothing else.

    The gate this replaced compared every entry EXCEPT this one, and then let
    this one change arbitrarily. So the single entry the whole change is about
    was the one place a repointed `source`, a widened `python-versions`, an
    added `dependencies` table or a flipped `optional` could arrive unread.
    """

    old_kernel = {key: value for key, value in old.items() if key[0] == KERNEL}
    new_kernel = {key: value for key, value in new.items() if key[0] == KERNEL}
    if not new_kernel:
        return [f"the resolved lock has no {KERNEL} entry"]
    if len(new_kernel) != 1 or len(old_kernel) != 1:
        return [
            f"expected exactly one {KERNEL} entry on each side, found "
            f"{len(old_kernel)} before and {len(new_kernel)} after"
        ]
    if old_kernel == new_kernel:
        return [f"{KERNEL} did not move; this lock says nothing"]

    before = next(iter(old_kernel.values()))
    after = next(iter(new_kernel.values()))
    problems = [
        f"{KERNEL} changed `{field}`, which a pin move may not change: "
        f"{before.get(field)!r} -> {after.get(field)!r}"
        for field in _changed_fields(before, after)
        if field not in KERNEL_MUTABLE_FIELDS
    ]
    source = after.get("source")
    if isinstance(source, dict) and source.get("url") != INDEX_URL:
        problems.append(
            f"{KERNEL} resolved from {source.get('url')!r}, not {INDEX_URL!r}"
        )
    return problems


def drift_problems(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Everything outside the moved pin that is not identical.

    The comparison this replaced keyed on `(name, version)` and compared file
    hashes, so a package silently repointed at a different index — a changed
    `[package.source]`, same name, same version, same files — resolved clean.
    So did changed `dependencies`, `extras`, `python-versions`, `optional`,
    `groups`, and every field of `[metadata]`. Whole entries, whole tables.
    """

    problems: list[str] = []
    old = _entries(before)
    new = _entries(after)

    old_other = {key: value for key, value in old.items() if key[0] != KERNEL}
    new_other = {key: value for key, value in new.items() if key[0] != KERNEL}

    for name, version in sorted(set(new_other) - set(old_other)):
        problems.append(f"{name} {version} appeared")
    for name, version in sorted(set(old_other) - set(new_other)):
        problems.append(f"{name} {version} disappeared")
    for key in sorted(set(old_other) & set(new_other)):
        fields = _changed_fields(old_other[key], new_other[key])
        if fields:
            problems.append(f"{key[0]} {key[1]} changed {', '.join(fields)}")

    problems += _kernel_entry_problems(old, new)

    old_meta = before.get("metadata", {})
    new_meta = after.get("metadata", {})
    for field in sorted(set(old_meta) | set(new_meta)):
        if field == "content-hash":
            continue
        if old_meta.get(field) != new_meta.get(field):
            problems.append(
                f"lock metadata `{field}` changed: "
                f"{old_meta.get(field)!r} -> {new_meta.get(field)!r}"
            )
    old_hash = old_meta.get("content-hash")
    new_hash = new_meta.get("content-hash")
    if not old_hash or not new_hash:
        problems.append("a lock is missing `metadata.content-hash` entirely")
    elif old_hash == new_hash:
        problems.append(
            "the content-hash is unchanged, so the manifest edit never reached "
            "the lock and this lock does not describe the edited manifest"
        )

    for table in sorted((set(before) | set(after)) - {"package", "metadata"}):
        if before.get(table) != after.get(table):
            problems.append(f"the lock's top-level `{table}` table changed")
    return problems


# ── evidence ────────────────────────────────────────────────────────────────


def credential_encodings(credential: str) -> dict[str, str]:
    """The forms of the credential worth looking for, keyed by a human label.

    An empty credential raises. A scan that cannot tell "no credential is
    present" from "there was no credential to look for" reports success on the
    run where the secret was never configured, and `grep -q -- ""` — the shape
    this replaced — matches every line of every file instead.

    Coverage is unchanged and still partial: not a credential split across
    lines, compressed or archived bytes, a hex rendering, non-UTF-8 bytes, or
    base64 at a non-zero offset inside a larger blob. That is why the only
    files it is pointed at are ones whose answer to a sighting is REFUSAL. No
    file is uploaded on the strength of this scan alone.
    """

    if not credential:
        raise Refusal(
            f"{CREDENTIAL_ENV} is unset or empty. There is nothing to scan the "
            "evidence for, so this scan cannot say the evidence is clean."
        )
    basic = f"{INDEX_USERNAME}:{credential}".encode()
    candidates = {
        "the credential itself": credential,
        "percent-encoded": urllib.parse.quote(credential, safe=""),
        "percent-encoded, spaces as +": urllib.parse.quote_plus(credential),
        "base64": base64.b64encode(credential.encode()).decode("ascii"),
        f"base64 basic-auth ({INDEX_USERNAME}:...)": base64.b64encode(basic).decode(
            "ascii"
        ),
    }
    first_label: dict[str, str] = {}
    for label, form in candidates.items():
        first_label.setdefault(form, label)
    return {label: form for form, label in first_label.items()}


def credential_sightings(paths: Iterable[Path], credential: str) -> list[str]:
    """`<file>: <which encoding>` for every place the credential still is."""

    forms = credential_encodings(credential)
    found: list[str] = []
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, form in forms.items():
            if form in text:
                found.append(f"{path.name}: {label}")
    return found


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pair_binding(digests: dict[str, str]) -> str:
    """One value over the manifest and the lock, in a fixed order.

    Recomputable by hand from the two digests printed beside it, which is the
    point: the consumer verifies the pair from the artifact alone.
    """

    missing = [name for name in PAIR if name not in digests]
    if missing:
        raise Refusal(f"cannot bind the pair without {', '.join(missing)}")
    body = "".join(f"{name} sha256:{digests[name]}\n" for name in PAIR)
    return sha256_hex(body.encode("utf-8"))


def sha256sums(digests: dict[str, str]) -> str:
    """The `sha256sum -c` format, so verification needs no tool of ours."""

    return "".join(f"{digests[name]}  {name}\n" for name in sorted(digests))


def coordinates_text(
    coordinates: dict[str, str],
    digests: dict[str, str],
    content_hash: str,
    binding: str,
) -> str:
    rows: list[tuple[str, str]] = list(coordinates.items())
    rows.append(("", ""))
    rows += [(f"sha256:{name}", digest) for name, digest in sorted(digests.items())]
    rows.append(("pair-binding", binding))
    rows.append(("lock-content-hash", content_hash))
    width = max(len(label) for label, _ in rows)
    lines = [
        f"{label.ljust(width)}  {value}".rstrip() if label else ""
        for label, value in rows
    ]
    return "\n".join(lines) + "\n\n" + _PAIR_PROSE


def build_evidence(
    out: Path,
    manifest: Path,
    lock: Path,
    coordinates: dict[str, str],
    credential: str,
) -> list[str]:
    """Write the artifact directory. Returns the sightings that must refuse.

    The manifest and the lock, and nothing else that carries resolver output.
    Every byte here is either one of those two files or derived from them by
    this module.
    """

    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, bytes] = {
        "pyproject.toml": manifest.read_bytes(),
        "poetry.lock": lock.read_bytes(),
    }
    for name, payload in written.items():
        (out / name).write_bytes(payload)

    digests = {name: sha256_hex(payload) for name, payload in written.items()}
    with (out / "poetry.lock").open("rb") as handle:
        content_hash = str(tomllib.load(handle)["metadata"]["content-hash"])
    (out / "coordinates.txt").write_text(
        coordinates_text(coordinates, digests, content_hash, pair_binding(digests)),
        encoding="utf-8",
    )
    everything = {
        path.name: sha256_hex(path.read_bytes())
        for path in out.iterdir()
        if path.is_file()
    }
    (out / "SHA256SUMS").write_text(sha256sums(everything), encoding="utf-8")
    return credential_sightings(
        [path for path in out.iterdir() if path.is_file()], credential
    )


# ── CLI ─────────────────────────────────────────────────────────────────────


def _report(subject: str, problems: list[str]) -> int:
    if problems:
        for problem in problems:
            print(f"::error::{subject}: {problem}")
        return 1
    print(f"{subject}: clean")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subcommands = parser.add_subparsers(dest="command", required=True)

    edit = subcommands.add_parser("set-kernel-version")
    edit.add_argument("--manifest", type=Path, required=True)
    edit.add_argument("--kernel-version", required=True)

    guard = subcommands.add_parser("manifest-guard")
    guard.add_argument("--manifest", type=Path, required=True)
    guard.add_argument("--checkout", type=Path, required=True)
    guard.add_argument("--kernel-version", required=True)

    fetch_bundle = subcommands.add_parser("acquire")
    fetch_bundle.add_argument("--manifest", type=Path, required=True)
    fetch_bundle.add_argument("--lock", type=Path, required=True)
    fetch_bundle.add_argument("--kernel-version", required=True)
    fetch_bundle.add_argument("--out", type=Path, required=True)

    aim = subcommands.add_parser("mirror-manifest")
    aim.add_argument("--manifest", type=Path, required=True)
    aim.add_argument("--mirror-url", required=True)

    restore = subcommands.add_parser("restore")
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--lock", type=Path, required=True)
    restore.add_argument("--mirror-url", required=True)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--digests", type=Path, required=True)
    verify.add_argument("--kernel-version", required=True)

    wheel_only = subcommands.add_parser("wheel-only")
    wheel_only.add_argument("--lock", type=Path, required=True)

    drift = subcommands.add_parser("drift")
    drift.add_argument("--before", type=Path, required=True)
    drift.add_argument("--after", type=Path, required=True)

    evidence = subcommands.add_parser("evidence")
    evidence.add_argument("--out", type=Path, required=True)
    evidence.add_argument("--manifest", type=Path, required=True)
    evidence.add_argument("--lock", type=Path, required=True)
    evidence.add_argument("--coordinate", action="append", default=[])
    return parser


def _run(args: argparse.Namespace) -> int:
    if args.command == "set-kernel-version":
        text = args.manifest.read_text(encoding="utf-8")
        args.manifest.write_text(
            replace_kernel_version(text, args.kernel_version), encoding="utf-8"
        )
        print(f"{KERNEL} -> {args.kernel_version}")
        return 0
    if args.command == "manifest-guard":
        return _report(
            "the tree under resolution",
            checkout_problems(args.checkout)
            + manifest_problems(_load_toml(args.manifest), args.kernel_version),
        )
    if args.command == "acquire":
        plan = acquisition_plan(
            _load_toml(args.manifest), _load_toml(args.lock), args.kernel_version
        )
        for package, version in sorted(plan.items()):
            print(f"bundling {package} {version}")
        digests = acquire(plan, args.out)
        for name, digest in sorted(digests.items()):
            print(f"{name}  {digest}")
        return 0
    if args.command == "mirror-manifest":
        args.manifest.write_text(
            point_at_mirror(args.manifest.read_text(encoding="utf-8"), args.mirror_url),
            encoding="utf-8",
        )
        print(f"the private source now points at {args.mirror_url}")
        return 0
    if args.command == "restore":
        args.manifest.write_text(
            restore_index_url(
                args.manifest.read_text(encoding="utf-8"), args.mirror_url
            ),
            encoding="utf-8",
        )
        args.lock.write_text(
            restore_index_url(
                args.lock.read_text(encoding="utf-8"),
                args.mirror_url,
                required=False,
            ),
            encoding="utf-8",
        )
        digest = poetry_content_hash(args.manifest, args.lock)
        args.lock.write_text(
            set_content_hash(args.lock.read_text(encoding="utf-8"), digest),
            encoding="utf-8",
        )
        print(f"the index URL is restored and the content-hash is {digest}")
        return 0
    if args.command == "verify":
        digests = json.loads(args.digests.read_text(encoding="utf-8"))
        return _report(
            "the lock against the published bytes",
            hash_problems(_load_toml(args.lock), digests, args.kernel_version),
        )
    if args.command == "wheel-only":
        return _report(
            "the resolution is wheel-only",
            lock_wheel_problems(_load_toml(args.lock)),
        )
    if args.command == "drift":
        return _report(
            "unrelated lock drift",
            drift_problems(_load_toml(args.before), _load_toml(args.after)),
        )
    if args.command != "evidence":
        raise Refusal(f"unknown command {args.command!r}")
    credential = os.environ.get(CREDENTIAL_ENV, "")
    coordinates = dict(item.split("=", 1) for item in args.coordinate if "=" in item)
    sightings = build_evidence(
        args.out, args.manifest, args.lock, coordinates, credential
    )
    return _report("the credential reached the evidence", sightings)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return _run(args)
    except Refusal as refusal:
        print(f"::error::{refusal}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
