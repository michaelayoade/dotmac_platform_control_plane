"""Every `run:` body in every workflow, and the `${{` openers inside it.

`.github/workflows/kernel-lock.yml` carried a shell comment —

    # Every coordinate crosses as a shell variable, never as a `${{ }}`

— that made the whole workflow undispatchable: `gh workflow run` returned
`HTTP 422: failed to parse workflow ... An expression was expected`. GitHub
templates `${{ ... }}` anywhere inside a `run:` body, comments included,
before bash ever sees the text; an empty pair of braces is not a valid
expression, and the parser error pointed at the enclosing `run: |` rather than
at the comment that actually caused it. PyYAML — and every other YAML-only
validator — accepted the file cleanly, because the defect is not a YAML
defect: `${{ }}` is ordinary string content to a YAML parser, and only GitHub
Actions' own expression templating treats it specially. That is why proving
the tree is valid YAML is not, and cannot be, the property this module
checks.

`run_block_expression_sites()` walks every workflow's `jobs.<job>.steps[]`,
finds the step's own `run:` field (never `env:`, `with:`, `if:`, or any other
structured field — those are the sanctioned path for a real expression), and
counts every `${{` opener inside its full text. It does this without
depending on PyYAML: `pyyaml` is not a declared dependency of this project —
it appears only as an optional extra of `fastapi`/`uvicorn` in `poetry.lock`
— and `tests/architecture/test_kernel_lock_workflow.py` already established
the house convention of a small indentation-based parser over the workflow
text for exactly that reason. This module follows the same convention,
generalised across every workflow file and keyed by (workflow, job, step
name) rather than scoped to one file.

The extraction cannot miss a heredoc or a comment: it does not try to
interpret the `run:` body as shell at all. It locates the field's own text —
the block scalar's marker line plus every line indented deeper than the
step's own top-level fields, or a single-line scalar's inline remainder — and
searches that whole text for the literal substring `${{`. A heredoc body and
a `#`-prefixed comment are just more characters inside that text; there is no
separate branch that would need to recognise either one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"

_JOB_HEADER = re.compile(r"^  ([A-Za-z_][\w.-]*):\s*$")
_ITEM = re.compile(r"^(\s*)-\s")


@dataclass(frozen=True)
class ExpressionSite:
    """One `run:` body that carries at least one `${{` opener."""

    workflow: str
    job: str
    step: str
    count: int

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.workflow, self.job, self.step)


def _job_blocks(text: str) -> dict[str, str]:
    """job name -> its raw text (everything nested under it), indentation kept.

    `test_the_workflow_parser_found_the_jobs` in `test_kernel_lock_workflow.py`
    keeps the single-file ancestor of this function honest; the sensitivity
    tests in this module's own test file do the same for the generalised one.
    """

    lines = text.splitlines()
    try:
        start = lines.index("jobs:")
    except ValueError:
        return {}
    blocks: dict[str, list[str]] = {}
    name: str | None = None
    for line in lines[start + 1 :]:
        header = _JOB_HEADER.match(line)
        if header:
            name = header.group(1)
            blocks[name] = []
            continue
        if line and not line[0].isspace():
            # Dedented out of the `jobs:` mapping entirely (e.g. a top-level
            # key after the last job).
            name = None
            continue
        if name is not None:
            blocks[name].append(line)
    return {job_name: "\n".join(body) for job_name, body in blocks.items()}


def _step_blocks(job_text: str) -> list[str]:
    """Every step's own text block (the `- ` line and everything under it)."""

    lines = job_text.splitlines()
    steps_at = next(
        (index for index, line in enumerate(lines) if line.strip() == "steps:"),
        None,
    )
    if steps_at is None:
        return []
    steps_indent = len(lines[steps_at]) - len(lines[steps_at].lstrip(" "))
    blocks: list[list[str]] = []
    item_indent: int | None = None
    for line in lines[steps_at + 1 :]:
        if not line.strip():
            if blocks:
                blocks[-1].append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= steps_indent:
            break  # dedented out of the `steps:` sequence
        item = _ITEM.match(line)
        if item and (item_indent is None or len(item.group(1)) == item_indent):
            item_indent = len(item.group(1))
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return ["\n".join(block) for block in blocks]


def _step_fields(step_text: str) -> dict[str, str]:
    """The step's own top-level fields (`name`, `run`, `env`, ...), each
    mapped to the full text of its value — inline remainder plus every more-
    deeply-indented continuation line, joined as-is."""

    lines = step_text.splitlines()
    first = lines[0]
    dash_indent = len(first) - len(first.lstrip(" "))
    field_indent = dash_indent + 2
    normalized = [(" " * field_indent) + re.sub(r"^\s*-\s?", "", first), *lines[1:]]
    key_pattern = re.compile(rf"^ {{{field_indent}}}([A-Za-z_][\w-]*):(.*)$")

    fields: dict[str, list[str]] = {}
    current: str | None = None
    for line in normalized:
        indent = len(line) - len(line.lstrip(" ")) if line.strip() else field_indent + 1
        match = key_pattern.match(line)
        if match and indent == field_indent:
            current = match.group(1)
            fields[current] = [match.group(2)]
        elif current is not None:
            fields[current].append(line)
    return {key: "\n".join(value) for key, value in fields.items()}


def _step_key(fields: dict[str, str], index: int) -> str:
    name = fields.get("name", "").strip()
    return name if name else f"<unnamed step index {index}>"


def run_block_expression_sites(
    workflows_dir: Path = WORKFLOWS_DIR,
) -> list[ExpressionSite]:
    """Every `${{` opener inside every `run:` body, across every workflow.

    Refuses the opener wherever it sits inside the body — a real
    interpolation, a shell comment, or a heredoc payload alike — because the
    opener alone is what breaks GitHub's parser; nothing here judges whether
    the surrounding text is "really" an expression.
    """

    sites: list[ExpressionSite] = []
    for path in sorted(workflows_dir.glob("*.yml")) + sorted(
        workflows_dir.glob("*.yaml")
    ):
        text = path.read_text(encoding="utf-8")
        for job_name, job_text in _job_blocks(text).items():
            for index, step_text in enumerate(_step_blocks(job_text)):
                fields = _step_fields(step_text)
                run = fields.get("run", "")
                count = run.count("${{")
                if count:
                    sites.append(
                        ExpressionSite(
                            path.name, job_name, _step_key(fields, index), count
                        )
                    )
    return sites


def baseline_mismatches(
    measured: dict[tuple[str, str, str], int],
    baseline: dict[tuple[str, str, str], int],
) -> tuple[
    dict[tuple[str, str, str], int],
    dict[tuple[str, str, str], int],
    dict[tuple[str, str, str], tuple[int, int]],
]:
    """The two-directional comparison a frozen baseline needs.

    Returns `(extra, missing, drifted)`:

    * `extra` — a site the tree carries that the baseline does not name. A
      genuinely new defect, or a retirement that only partly landed.
    * `missing` — a baseline entry the tree no longer carries a matching
      `${{` opener for. The baseline was not lowered in the change that
      retired the site, so it would silently keep "proving" a retirement
      that has not actually been recorded.
    * `drifted` — a site both name, but whose count moved without the
      baseline moving with it.
    """

    extra = {key: count for key, count in measured.items() if key not in baseline}
    missing = {key: count for key, count in baseline.items() if key not in measured}
    drifted = {
        key: (baseline[key], measured[key])
        for key in measured
        if key in baseline and measured[key] != baseline[key]
    }
    return extra, missing, drifted


#: The two-directional frozen baseline. Every entry here is a REAL
#: interpolation (not a comment) that predates this guard, keyed by
#: (workflow file name, job name, step name) — never by step index, since an
#: inserted step would shift an index and silently mis-attribute a row, the
#: same rot as citing a line number that moves under the next edit.
#:
#: `kernel-lock.yml` carries no entry: its one site was a shell comment, not
#: an interpolation, and it is repaired (not retired) directly in this
#: change.
#:
#: RETIREMENT. These are scheduled for two later PRs — `production-image.yml`
#: first, then `production-deploy.yml` — each removing only its own entries.
#: The baseline is two-directional: `test_only_the_frozen_baseline_carries_a_
#: run_block_expression` fails if the measured count RISES past this table
#: (an unrecorded new site, or a partial retirement) or FALLS below it
#: without this table being lowered in the same change (a stale entry
#: hiding that a retirement happened). The retiring PR always shrinks this
#: table and this table only — never widens it, never rewrites another row.
#: UNNAMED STEPS. A step with a `run:` body and no `name:` is keyed
#: `<unnamed step index N>`, so it can never pass silently — it fails as an
#: unbaselined site. That key is index-based, which is the same fragile shape
#: this table avoids elsewhere: if an unnamed site were ever ADMITTED here,
#: inserting an earlier step in its job would re-key it and produce a false
#: `missing` plus a false `extra` with nothing about the expression changed.
#: No current row is unnamed and none should be. If one ever needs to be, give
#: the step a name rather than baselining an index.
RUN_BLOCK_EXPRESSION_BASELINE: dict[tuple[str, str, str], int] = {
    ("production-deploy.yml", "deploy", "Verify that the image exists"): 1,
    (
        "production-image.yml",
        "candidate",
        "Verify the source revision earned its way here",
    ): 1,
    ("production-image.yml", "candidate", "Build the candidate"): 1,
    ("production-image.yml", "candidate", "Record the candidate's identity"): 1,
    ("production-image.yml", "candidate", "Authenticate to GHCR"): 1,
    ("production-image.yml", "candidate", "Publish the accepted candidate"): 1,
    (
        "production-image.yml",
        "candidate",
        "Prove the registry holds the accepted candidate",
    ): 5,
    ("production-image.yml", "candidate", "Emit the release receipt"): 8,
}
