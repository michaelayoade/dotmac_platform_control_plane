"""Own the equality and immutability rule for the three Governance pins."""

from __future__ import annotations

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = REPO_ROOT / ".dotmac" / "standards-profile.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "engineering-standards.yml"
PLACEHOLDER = "PENDING-APPROVAL"
SHA = re.compile(r"^[0-9a-f]{40}$")
_ENV_REF = re.compile(
    r"^\s*GOVERNANCE_REF:\s*[\"']?([^\"'\s#]+)[\"']?\s*$", re.MULTILINE
)
_USES_REF = re.compile(
    r"^\s*uses:\s*michaelayoade/dotmac_governance/"
    r"\.github/actions/standards-check@([^\s#]+)\s*$",
    re.MULTILINE,
)


def read_pins(root: pathlib.Path = REPO_ROOT) -> tuple[str, str, str]:
    """Return profile, workflow-environment and workflow-action pins."""
    profile_path = root / ".dotmac" / "standards-profile.json"
    workflow_path = root / ".github" / "workflows" / "engineering-standards.yml"
    revision = ""
    if profile_path.is_file():
        model = json.loads(profile_path.read_text(encoding="utf-8")).get(
            "governance_model", {}
        )
        revision = str(model.get("revision", ""))
    text = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    env_match = _ENV_REF.search(text)
    uses_match = _USES_REF.search(text)
    return (
        revision,
        env_match.group(1) if env_match else "",
        uses_match.group(1) if uses_match else "",
    )


def problems(profile_revision: str, env_ref: str, uses_ref: str) -> list[str]:
    """Report incoherent, placeholder or moving Governance references."""
    pins = {
        "profile governance_model.revision": profile_revision,
        "workflow GOVERNANCE_REF": env_ref,
        "workflow uses ref": uses_ref,
    }
    if len(set(pins.values())) != 1:
        rendered = ", ".join(f"{name}={value!r}" for name, value in pins.items())
        return [f"the Governance pins disagree: {rendered}"]
    pin = profile_revision
    if pin == PLACEHOLDER:
        return ["the Governance pin is still PENDING-APPROVAL"]
    if not SHA.fullmatch(pin):
        return [f"{pin!r} is not a lower-case 40-character Git SHA"]
    return []


def main() -> int:
    found = problems(*read_pins())
    if not found:
        print(f"governance pin OK: {read_pins()[0]}")
        return 0
    print("Governance pin preflight FAILED:", file=sys.stderr)
    for item in found:
        print(f"  - {item}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
