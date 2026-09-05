"""The four refusals `.github/workflows/kernel-lock.yml` needs, out of the YAML.

A lock entry for `dotmac-kernel` is the one part of a pin change that cannot be
written by hand: its two sha256 values are facts about published artifacts. The
workflow that resolves them holds `FORGEJO_READ_TOKEN`, so every check it makes
is a security check, and a security check embedded in a `run:` block is a check
nobody can plant a defect against.

So the checks live here, as functions, and `tests/architecture/
test_kernel_lock_workflow.py` plants a defect against each one. The workflow
runs this module from the TRUSTED checkout — the commit that defines the
workflow — never from the ref under resolution.

Four subjects, deliberately separate:

* `set-kernel-version` — move the pin in the manifest, refusing unless exactly
  one declaration matched. Two matches means guessing which one is the pin.
* `manifest-guard` — the ref under resolution supplies the manifest, and
  Poetry keys HTTP credentials by source NAME. A manifest that keeps the name
  `forgejo` and moves its URL would have the credential posted to the new
  host by Poetry itself, with no code execution anywhere. This refuses that,
  and refuses the dependency forms whose resolution executes code from
  somewhere the index does not name.
* `drift` — the whole lock outside the `dotmac-kernel` entry must be
  identical. Not three fields of it.
* `evidence` — assemble what leaves the runner: the manifest/lock PAIR bound
  to each other and to this run, a scrubbed resolver log, and a scan that
  refuses rather than passes when there is no credential to look for.

## What the credential scan does not cover

`credential_encodings` names the forms a credential can plausibly take in a
resolver log: itself, percent-encoded, percent-encoded with `+`, base64, and
base64 of the `ci-reader:<credential>` basic-auth pair. It does NOT cover a
credential split across lines, compressed or archived bytes, a hex or otherwise
re-encoded rendering, bytes that are not UTF-8, or base64 of a larger blob that
merely CONTAINS the credential — base64 is offset-sensitive, so a credential
sitting at a non-zero offset inside an encoded region does not match. This is a
belt over braces, not a proof of absence; the property the workflow actually
relies on is that Poetry does not echo the credential.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import tomllib
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any

#: The private index this assembly resolves Dotmac packages from. The workflow
#: names the same URL for its own `curl`; a drift between the two is caught by
#: `test_kernel_lock_workflow.py`.
INDEX_URL = "https://registry.dotmac.io/api/packages/dotmac/pypi/simple"

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

#: The two files a consumer must apply TOGETHER. The lock's content-hash is
#: derived from the manifest, so either one alone describes a tree that does
#: not exist.
PAIR = ("pyproject.toml", "poetry.lock")

REDACTED = "***REDACTED***"

_KERNEL_DECLARATION = re.compile(r'(dotmac-kernel = \{ version = ")[^"]+(")')

#: Dependency forms whose resolution reads or executes something the index does
#: not name. `path` and `url` reach outside the index; `git` clones and can run
#: a build backend from the cloned tree.
_OFF_INDEX_DEPENDENCY_KEYS = ("path", "git", "url")

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


# ── manifest-guard ──────────────────────────────────────────────────────────


def _dependency_tables(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    poetry = manifest.get("tool", {}).get("poetry", {})
    tables: list[tuple[str, dict[str, Any]]] = []
    main = poetry.get("dependencies")
    if isinstance(main, dict):
        tables.append(("tool.poetry.dependencies", main))
    for name, group in sorted(poetry.get("group", {}).items()):
        deps = group.get("dependencies") if isinstance(group, dict) else None
        if isinstance(deps, dict):
            tables.append((f"tool.poetry.group.{name}.dependencies", deps))
    return tables


def manifest_problems(manifest: dict[str, Any], kernel_version: str) -> list[str]:
    """Everything about this manifest that would misdirect the credential.

    The threat is not code execution. Poetry resolves `POETRY_HTTP_BASIC_
    FORGEJO_PASSWORD` by the source NAME `forgejo`, and the ref under
    resolution owns the URL that name points at. Changing the URL and keeping
    the name is enough to have Poetry send the credential to another host,
    with nothing untrusted ever executing.

    PREMISE: this reads the legacy `[tool.poetry]` layout, which is the layout
    this assembly uses. A ref that converted the manifest to PEP 621 `[project]`
    is refused rather than waved through — `replace_kernel_version` fails on it
    first, and if it did not, this reports no pin to resolve. It is not silently
    unexamined.
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

    for table, deps in _dependency_tables(manifest):
        for name, spec in sorted(deps.items()):
            if not isinstance(spec, dict):
                continue
            for key in _OFF_INDEX_DEPENDENCY_KEYS:
                if key in spec:
                    problems.append(
                        f"{table}.{name} is a `{key}` dependency; resolving it "
                        "reads or executes something the index does not name"
                    )
            source = spec.get("source")
            if source is not None and source != INDEX_SOURCE_NAME:
                problems.append(
                    f"{table}.{name} resolves from source {source!r}, which "
                    "this job does not hold a credential for"
                )

    if "requires-plugins" in manifest.get("tool", {}).get("poetry", {}):
        problems.append(
            "`tool.poetry.requires-plugins` is declared; Poetry installs and "
            "imports plugins before it resolves, which is arbitrary code in "
            "the step that holds the credential"
        )

    kernel = None
    for _table, deps in _dependency_tables(manifest):
        if KERNEL in deps:
            kernel = deps[KERNEL]
            break
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


def drift_problems(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Everything outside the `dotmac-kernel` entry that is not identical.

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

    old_kernel = {key: value for key, value in old.items() if key[0] == KERNEL}
    new_kernel = {key: value for key, value in new.items() if key[0] == KERNEL}
    if not new_kernel:
        problems.append(f"the resolved lock has no {KERNEL} entry")
    elif old_kernel == new_kernel:
        problems.append(f"{KERNEL} did not move; this lock says nothing")

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


def scrub(text: str, credential: str) -> str:
    """Replace every known encoding of the credential, longest form first."""

    forms = sorted(credential_encodings(credential).values(), key=len, reverse=True)
    for form in forms:
        text = text.replace(form, REDACTED)
    return text


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
    resolver_log: Path,
    coordinates: dict[str, str],
    credential: str,
) -> list[str]:
    """Write the artifact directory. Returns the sightings that must refuse."""

    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, bytes] = {
        "pyproject.toml": manifest.read_bytes(),
        "poetry.lock": lock.read_bytes(),
    }
    log = resolver_log.read_text(encoding="utf-8", errors="replace")
    written["resolver.log"] = scrub(log, credential).encode("utf-8")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subcommands = parser.add_subparsers(dest="command", required=True)

    edit = subcommands.add_parser("set-kernel-version")
    edit.add_argument("--manifest", type=Path, required=True)
    edit.add_argument("--kernel-version", required=True)

    guard = subcommands.add_parser("manifest-guard")
    guard.add_argument("--manifest", type=Path, required=True)
    guard.add_argument("--kernel-version", required=True)

    drift = subcommands.add_parser("drift")
    drift.add_argument("--before", type=Path, required=True)
    drift.add_argument("--after", type=Path, required=True)

    evidence = subcommands.add_parser("evidence")
    evidence.add_argument("--out", type=Path, required=True)
    evidence.add_argument("--manifest", type=Path, required=True)
    evidence.add_argument("--lock", type=Path, required=True)
    evidence.add_argument("--resolver-log", type=Path, required=True)
    evidence.add_argument("--coordinate", action="append", default=[])

    args = parser.parse_args(argv)
    try:
        if args.command == "set-kernel-version":
            text = args.manifest.read_text(encoding="utf-8")
            args.manifest.write_text(
                replace_kernel_version(text, args.kernel_version), encoding="utf-8"
            )
            print(f"{KERNEL} -> {args.kernel_version}")
            return 0
        if args.command == "manifest-guard":
            return _report(
                "the manifest under resolution",
                manifest_problems(_load_toml(args.manifest), args.kernel_version),
            )
        if args.command == "drift":
            return _report(
                "unrelated lock drift",
                drift_problems(_load_toml(args.before), _load_toml(args.after)),
            )
        if args.command != "evidence":
            raise Refusal(f"unknown command {args.command!r}")
        credential = os.environ.get(CREDENTIAL_ENV, "")
        coordinates = dict(
            item.split("=", 1) for item in args.coordinate if "=" in item
        )
        sightings = build_evidence(
            args.out,
            args.manifest,
            args.lock,
            args.resolver_log,
            coordinates,
            credential,
        )
        return _report("the credential reached the evidence", sightings)
    except Refusal as refusal:
        print(f"::error::{refusal}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
