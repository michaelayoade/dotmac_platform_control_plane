#!/usr/bin/env python3
"""Derive the next reviewed descriptor without rewriting deployed truth.

``deploy/product.toml`` and ``deploy/product-manifest.json`` describe what is
running. A dependency adoption changes the composition before a new image
exists, so its descriptor lives under ``deploy/prospective`` until a successful
receipt promotes those exact bytes. Its manifest path is content-addressed:
promotion cannot leave accepted truth pointing at a mutable prospective file.
Image identity and source revision remain the current values here; candidate
derivation is still the sole owner of those two circular fields.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = ROOT / "deploy" / "product.toml"
PROSPECTIVE_MANIFEST = ROOT / "deploy" / "prospective" / "product-manifest.json"
PROSPECTIVE = ROOT / "deploy" / "prospective" / "product.toml"

_OLD_MANIFEST_PATH = 'manifest_path = "deploy/product-manifest.json"'
_OLD_CONTROL_HEAD = '  "dc_0002_canonical_plan_digest",'
_NEW_CONTROL_HEAD = '  "dc_0006_observation_key_identity",'


def manifest_digest() -> str:
    document = json.loads(PROSPECTIVE_MANIFEST.read_text(encoding="utf-8"))
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def immutable_manifest_relative_path() -> str:
    digest = manifest_digest().removeprefix("sha256:")
    path = ROOT / "deploy" / "manifests" / f"sha256-{digest}.json"
    if not path.is_file():
        raise SystemExit(
            f"content-addressed prospective manifest {path} is absent; "
            "run scripts/generate_product_manifest.py first"
        )
    return path.relative_to(ROOT).as_posix()


def render() -> str:
    accepted = ACCEPTED.read_text(encoding="utf-8")
    for old in (_OLD_MANIFEST_PATH, _OLD_CONTROL_HEAD):
        if accepted.count(old) != 1:
            count = accepted.count(old)
            raise SystemExit(
                f"accepted descriptor contains {count} copies of {old!r}; "
                "the prospective transform no longer has one unambiguous input"
            )
    marker = 'manifest_digest = "'
    start = accepted.find(marker)
    if start < 0 or accepted.find(marker, start + 1) >= 0:
        raise SystemExit("accepted descriptor has no unique assembly manifest digest")
    value_start = start + len(marker)
    value_end = accepted.find('"', value_start)
    old_digest = accepted[value_start:value_end]
    if not old_digest.startswith("sha256:") or len(old_digest) != 71:
        raise SystemExit("accepted descriptor assembly manifest digest is malformed")
    new_manifest_path = (
        f'manifest_path = "{immutable_manifest_relative_path()}"'
    )
    return (
        accepted.replace(_OLD_MANIFEST_PATH, new_manifest_path)
        .replace(_OLD_CONTROL_HEAD, _NEW_CONTROL_HEAD)
        .replace(old_digest, manifest_digest(), 1)
    )


def main() -> int:
    PROSPECTIVE.parent.mkdir(parents=True, exist_ok=True)
    PROSPECTIVE.write_text(render(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
