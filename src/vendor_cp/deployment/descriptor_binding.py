"""CP descriptor declarations, distinct from independently observed source state.

Historical promotion advances the image and database halves independently.
These facts describe the unchanged Git blob; they never replace an OCI label
or a fenced database observation. Target admission remains stricter.
"""

from __future__ import annotations

import re
import tomllib
from typing import TypedDict

from vendor_cp.deploy_agent.contracts import require


class SourceDescriptorDeclarations(TypedDict):
    image_reference: str
    source_revision: str
    migration_heads: list[str] | None


def source_descriptor_declarations(raw: bytes) -> SourceDescriptorDeclarations:
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("transition source descriptor is not UTF-8 TOML") from error
    image = document.get("image")
    require(
        document.get("product") == "dotmac_vendor_control_plane"
        and document.get("environment") == "production"
        and isinstance(image, dict),
        "source_descriptor_identity_mismatch",
    )
    if not isinstance(image, dict):
        raise ValueError("source descriptor image declaration missing")
    reference, revision = image.get("reference"), image.get("source_revision")
    require(
        isinstance(reference, str)
        and re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", reference) is not None
        and isinstance(revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
        "source_descriptor_declaration_invalid",
    )
    migration = document.get("migration", {})
    require(isinstance(migration, dict), "source_descriptor_declaration_invalid")
    if not isinstance(migration, dict):
        raise ValueError("source descriptor migration declaration invalid")
    heads = migration.get("expected_heads")
    require(
        heads is None
        or isinstance(heads, list)
        and all(isinstance(head, str) and bool(head) for head in heads)
        and len(set(heads)) == len(heads),
        "source_descriptor_declaration_invalid",
    )
    # Runtime type checks above are kept independent of target-image equality.
    if not isinstance(reference, str) or not isinstance(revision, str):
        raise ValueError("source descriptor declaration type mismatch")
    return {
        "image_reference": reference,
        "source_revision": revision,
        "migration_heads": heads,
    }
