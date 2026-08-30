from __future__ import annotations

import copy
import json
import runpy
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = ROOT / "docs" / "operations" / "pre-rename-ghcr-package-state.json"
_settings_verdicts = runpy.run_path(
    str(ROOT / "scripts" / "verify_ghcr_package_state.py")
)["_settings_verdicts"]


def _capture() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(CAPTURE.read_text()))


def test_authenticated_pre_rename_settings_are_complete() -> None:
    frozen = _capture()

    assert (
        _settings_verdicts(
            frozen,
            observation_name="pre_rename_observation",
            expected_repository="michaelayoade/dotmac_vendor_control_plane",
        )
        == []
    )


def test_post_rename_settings_cannot_pass_before_the_second_observation() -> None:
    frozen = _capture()

    failures = _settings_verdicts(
        frozen,
        observation_name="post_rename_observation",
        expected_repository="michaelayoade/dotmac_platform_control_plane",
    )

    assert any("PERMISSION INHERITANCE UNMEASURED" in item for item in failures)
    assert any("ACTIONS ACCESS UNMEASURED" in item for item in failures)


def test_post_rename_settings_accept_only_the_renamed_source_repository() -> None:
    frozen = copy.deepcopy(_capture())
    required = frozen["required_settings"]
    required["permission_inheritance_enabled"]["post_rename_observation"] = {
        "observed": True
    }
    required["actions_access_repositories"]["post_rename_observation"] = {
        "observed": ["michaelayoade/dotmac_platform_control_plane"],
        "roles": {"michaelayoade/dotmac_platform_control_plane": "Admin"},
    }

    assert (
        _settings_verdicts(
            frozen,
            observation_name="post_rename_observation",
            expected_repository="michaelayoade/dotmac_platform_control_plane",
        )
        == []
    )


def test_broader_actions_access_is_refused_even_when_inheritance_is_enabled() -> None:
    frozen = copy.deepcopy(_capture())
    required = frozen["required_settings"]
    required["permission_inheritance_enabled"]["post_rename_observation"] = {
        "observed": True
    }
    required["actions_access_repositories"]["post_rename_observation"] = {
        "observed": [
            "michaelayoade/dotmac_platform_control_plane",
            "michaelayoade/unrelated",
        ],
        "roles": {
            "michaelayoade/dotmac_platform_control_plane": "Admin",
            "michaelayoade/unrelated": "Read",
        },
    }

    failures = _settings_verdicts(
        frozen,
        observation_name="post_rename_observation",
        expected_repository="michaelayoade/dotmac_platform_control_plane",
    )

    assert any("ACTIONS ACCESS:" in item for item in failures)
    assert any("ACTIONS ACCESS ROLE:" in item for item in failures)
