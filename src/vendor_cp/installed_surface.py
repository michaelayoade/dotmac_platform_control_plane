"""What a production invocation of this assembly is allowed to look like.

The assembly is installed as a WHEEL now, and its operator surface is the
console script this distribution declares. This module holds the ledger that
keeps it that way: the shapes a production instruction must not grow, and the set
of occurrences that still exist, each with the reason it is still there and who
retires it.

## Set-shaped, and two-directional

The baseline records the MATCHED TEXT of every occurrence, not a count. A count
survives a swap — one path retired while another gains the same ability — and a
swap is precisely the move worth catching, because it looks like progress in
the diff and changes nothing in the estate. Comparing sets means a new
occurrence fails until it is declared, a retired one fails until the declaration
is lowered, and an exchange of one for another fails in both directions at once.

## Entry-point identity, not a string match

`sanctioned_entry_points` does not contain the console script's name. It reads
the names the INSTALLER recorded for this distribution, because a literal would
reintroduce exactly the substring matching this is meant to replace — and
because a sanctioned invocation runs code that lives inside the installed
distribution, which is not in this tree, so it can never appear in a scan of it.
An unsanctioned one is in the tree and always does. No question of intent is
ever asked: there is no allowlisted filename, no "is this the good compose
call?", and no comment to trust. A delegation sitting next to a direct call
does not launder it.

Two properties keep that honest:

* **An unresolvable distribution is UNMONITORED, not a pass.** When the
  distribution is not installed, `sanctioned_entry_points` returns `None` rather
  than an empty set, and the caller must say the region is unmonitored. An
  absent guard is not a passed guard.
* **Installed-or-not is deliberately absent from the baseline.** Whether this
  distribution happens to be installed is a property of where the check runs,
  not of the product, and freezing a laptop's answer into a committed file is
  how a local virtual environment becomes a fleet fact.

There is a near-match hazard in this shape generally: a console-script name can
be a PREFIX of its own distribution name — the deployment foundation's script is
a prefix of the distribution that ships it — and a naive substring test then
passes on the very line that makes it an identity check. This pair does not
collide that way, but the class does, so
`tests/architecture/test_installed_cli.py` checks it deliberately rather than
assuming this pair is safe.

Neither name is written here, and the guard that keeps them out is the one
directly above: naming the script in this file would be the first step back to
the substring matching it replaces. The test enforces that, and it caught this
paragraph doing exactly that on its first run.

## Why these five shapes

Each is a way of running production code from a mutable checkout instead of from
an installed artifact, and each has cost something somewhere:

* `PYTHONPATH=src` — the import root is a directory somebody rsynced, so what
  runs is whatever was last copied there, and no version answers for it.
* `python scripts/…` / `python3 scripts/…` — the entry point is a path, not a
  name, so it resolves relative to a working directory rather than to a package.
* an `ops` container given a script PATH — same defect wearing a container.
* rsync of executable deployment assets — the executable half of a deployment
  arrives out of band from the image it deploys, so the two can disagree.
* checkout-relative production commands — `cd $TARGET_DIR && …` makes the
  deployment's behaviour a function of a directory's current contents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Final

from vendor_cp.identity import DISTRIBUTION


@dataclass(frozen=True, slots=True)
class Shape:
    """One production shape that must not spread."""

    kind: str
    pattern: re.Pattern[str]
    why: str


#: The five refused shapes. Written as one table so the scanner, the ledger and
#: the documentation cannot disagree about what is being looked for.
SHAPES: Final[tuple[Shape, ...]] = (
    Shape(
        "pythonpath_src",
        re.compile(r"PYTHONPATH=\S*src\b"),
        "the import root is a copied directory, so nothing answers for its version",
    ),
    Shape(
        "python_scripts",
        re.compile(r"\bpython3?\s+(?:-\S+\s+)*scripts/\S+"),
        "the entry point is a path relative to a working directory, not a name",
    ),
    Shape(
        "ops_container_script_path",
        re.compile(r"\bops\s+scripts/\S+"),
        "a container handed a script path is the same defect wearing an image",
    ),
    Shape(
        "rsync_executable_asset",
        # Applied ONLY inside an rsync argument vector — see `_rsync_payload`.
        # A repository-wide search for script paths would flag every sentence
        # that mentions one, and a ledger full of prose is a ledger nobody
        # reads. What is refused is the TRANSFER, not the noun.
        re.compile(r"\S+\.(?:sh|py)\b"),
        "the executable half of a deployment arrives out of band from its image",
    ),
    Shape(
        "checkout_relative_production_command",
        re.compile(r"cd\s+'?\$?\{?[A-Za-z_]*TARGET_DIR|cd\s+/opt/dotmac/\S+"),
        "deployment behaviour becomes a function of a directory's contents",
    ),
)

#: Files whose whole job is to NAME these shapes. Counting them would count the
#: ledger as an occurrence, which is the same mistake as counting a symbol
#: inventory as a call site.
LEDGERS: Final[tuple[str, ...]] = (
    "src/vendor_cp/installed_surface.py",
    "tests/architecture/test_installed_cli.py",
    "docs/operations/installed-cli.md",
)

#: Extensions worth reading. A binary or a lock file cannot carry an invocation.
SCANNED_SUFFIXES: Final[frozenset[str]] = frozenset(
    {".py", ".sh", ".yml", ".yaml", ".toml", ".md", ".ini", ".example", ".cfg", ""}
)

#: Directories that hold no production instruction. `docs/adr` is the record of
#: decisions already taken: an ADR quoting the command it retired is history,
#: and a ratchet that made history fail would push people to edit the record.
SKIPPED_DIRS: Final[frozenset[str]] = frozenset(
    {".git", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
)
SKIPPED_PREFIXES: Final[tuple[str, ...]] = ("docs/adr/",)


def scan(root: Path) -> dict[tuple[str, str], tuple[str, ...]]:
    """Every occurrence of a refused shape under `root`, as matched text.

    The value is the sorted distinct matched strings rather than a number, so a
    file that swaps one refused command for another fails even though it still
    has exactly one.
    """
    found: dict[tuple[str, str], set[str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        relative = path.relative_to(root).as_posix()
        if relative in LEDGERS or relative.startswith(SKIPPED_PREFIXES):
            continue
        if path.suffix not in SCANNED_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for shape in SHAPES:
            haystack = (
                _rsync_payload(text) if shape.kind == "rsync_executable_asset" else text
            )
            for match in shape.pattern.findall(haystack):
                found.setdefault((shape.kind, relative), set()).add(match)
    return {key: tuple(sorted(values)) for key, values in sorted(found.items())}


def _rsync_payload(text: str) -> str:
    """Just the lines that are part of an `rsync` argument vector.

    A continuation-aware slice rather than a whole-file search, because the
    shape being refused is the TRANSFER of an executable deployment asset, not
    a mention of one. A pattern that could not tell those apart would put every
    sentence naming a script into the ledger, and a ledger that large stops
    being read — which is the failure mode that makes a ratchet decorative.
    """
    lines: list[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"\brsync\b", stripped):
            inside = True
        if inside:
            lines.append(line)
            if not stripped.endswith("\\"):
                inside = False
    return "\n".join(lines)


def sanctioned_entry_points() -> frozenset[str] | None:
    """The console-script names the INSTALLER recorded for this distribution.

    `None` when the distribution is not installed. That is not an empty set and
    must not be treated as one: an unresolvable distribution means the region is
    UNMONITORED, and reporting an absent guard as a passed guard is the failure
    this return type exists to prevent.

    The names are never written down here. A sanctioned invocation runs code
    inside the installed distribution — which is not in this tree — so it can
    never appear in `scan`; an unsanctioned one is in the tree and always does.
    """
    try:
        distribution = metadata.distribution(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return None
    return frozenset(
        entry.name
        for entry in distribution.entry_points
        if entry.group == "console_scripts"
    )


#: The measured set of occurrences that still exist, each with why and whose
#: retirement removes it. This is DEBT, declared: the shapes above are refused
#: for new code, and everything here is a place that has not been converted yet.
#:
#: Lowering an entry is part of the change that retires it. Raising one requires
#: saying, in this file, why a new production instruction needs a shape the
#: repository has decided against.
BASELINE: Final[dict[tuple[str, str], tuple[str, ...]]] = {
    (
        "checkout_relative_production_command",
        ".github/workflows/production-deploy.yml",
    ): ("cd '$TARGET_DIR",),
    (
        "checkout_relative_production_command",
        "docs/operations/production-deployment.md",
    ): ("cd /opt/dotmac/vendor-control-plane",),
    ("python_scripts", ".github/workflows/ci.yml"): ("python scripts/kernel_floor.py",),
    ("python_scripts", ".github/workflows/engineering-standards.yml"): (
        "python3 scripts/check_governance_pin.py",
    ),
    ("python_scripts", ".github/workflows/production-deploy.yml"): (
        "python3 scripts/materialize_production_secrets.py",
    ),
    ("python_scripts", "docs/operations/production-deployment.md"): (
        "python3 scripts/materialize_production_secrets.py",
    ),
    ("python_scripts", "scripts/reconcile_backfill_shadow.py"): (
        "python scripts/reconcile_backfill_shadow.py",
    ),
    ("python_scripts", "scripts/verify_ghcr_package_state.py"): (
        "python3 scripts/verify_ghcr_package_state.py",
    ),
    ("pythonpath_src", ".github/workflows/production-deploy.yml"): ("PYTHONPATH=src",),
    ("pythonpath_src", "docs/operations/production-deployment.md"): ("PYTHONPATH=src",),
    ("pythonpath_src", "src/vendor_cp/production_secrets.py"): (
        "PYTHONPATH={target_dir}/src",
    ),
    ("rsync_executable_asset", ".github/workflows/production-deploy.yml"): (
        "deploy/postgres/init-roles.sh",
        "scripts/deploy_production.sh",
        "scripts/deploy_production_with_registry_token.sh",
        "scripts/materialize_production_secrets.py",
        "src/vendor_cp/product_release_pins.py",
        "src/vendor_cp/production_secrets.py",
    ),
    ("rsync_executable_asset", "docs/operations/production-deployment.md"): (
        "scripts/materialize_production_secrets.py",
        "src/vendor_cp/product_release_pins.py",
        "src/vendor_cp/production_secrets.py",
    ),
}

#: Why each surviving occurrence is still here. Keyed by file, because the
#: reason is a property of the caller rather than of the pattern that found it.
#:
#: Every entry names a RETIREMENT CONDITION, not a preference. An exemption that
#: cannot say what would remove it is an exemption nobody will remove.
BASELINE_REASONS: Final[dict[str, str]] = {
    ".github/workflows/ci.yml": (
        "The `kernel-pin` lane's SUBJECT is this checkout's own declaration — "
        "which kernel `pyproject.toml` pins, which submodules the composed "
        "source imports — compared against the private index and against a "
        "scratch install of the version the pin excludes. An installed console "
        "script answers for the artifact it was built into and cannot answer "
        "for the tree that declared it, which is the one question here. This is "
        "also a hosted CI runner with a checkout by definition, not a "
        "production host: no operator runs it and no deployment depends on it. "
        "Retires if the pin derivation is ever needed at runtime rather than at "
        "review time, at which point it becomes a diagnose command on the "
        "installed console script, with a declared owner like every other "
        "operator surface. (That script is deliberately not named here: this "
        "module may not hold its name as a literal, because the checks that "
        "need it read it from installed metadata.)"
    ),
    ".github/workflows/production-deploy.yml": (
        "The host-side leg runs on the TARGET, outside any container, against an "
        "rsync'd partial checkout that has no installed package — so the secret "
        "materializer genuinely has no console script to call. Retires when the "
        "deployment foundation owns the host leg and the descriptor names an "
        "image rather than a directory (WAVE 3). The `cd $TARGET_DIR` is the "
        "Compose project directory and goes with it."
    ),
    "docs/operations/production-deployment.md": (
        "The runbook mirrors the workflow above and retires with it. Its "
        "`cd /opt/dotmac/vendor-control-plane` is where the compose file and "
        "`.env` live, not an import root — declared rather than exempted, "
        "because a shape carved out by hand is a shape nobody measures again."
    ),
    "src/vendor_cp/production_secrets.py": (
        "Builds the remote leg's argument vector for the workflow above. It is "
        "the same debt seen from the sending side and retires in the same "
        "change; separating them would let one survive the other."
    ),
    ".github/workflows/engineering-standards.yml": (
        "`check_governance_pin.py` is stdlib-only and imports nothing from this "
        "assembly, which is why its CI job deliberately has no install step. "
        "Converting it to a console script would ADD an installation to a job "
        "whose value is that it needs none. Held at exactly one occurrence."
    ),
    "scripts/reconcile_backfill_shadow.py": (
        "A rehearsal tool's own usage line. It connects to nothing, emits SQL "
        "rather than executing it, and is never a production instruction. "
        "Retires with ADR-0012's backfill."
    ),
    "scripts/verify_ghcr_package_state.py": (
        "A workstation operator tool's own usage line. It needs a short-lived "
        "`read:packages` credential CI must not hold, so it deliberately runs "
        "nowhere near production. Retires when the rename equality it checks is "
        "closed out."
    ),
}


__all__ = [
    "BASELINE",
    "BASELINE_REASONS",
    "LEDGERS",
    "SCANNED_SUFFIXES",
    "SHAPES",
    "SKIPPED_DIRS",
    "SKIPPED_PREFIXES",
    "Shape",
    "sanctioned_entry_points",
    "scan",
]
