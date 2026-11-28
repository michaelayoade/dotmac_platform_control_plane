#!/usr/bin/env python3
"""Prepare one source-only Dockerfile overlay; never invoke a builder."""
import argparse
import hashlib
import json
from pathlib import Path

ORIGINAL_SHA256 = "6e8d895d0aece83391c6198e3766d9b2bcfcde79c5874b9398b201c970823340"
OLD = b'''RUN --mount=type=secret,id=forgejo_token \\
    POETRY_HTTP_BASIC_FORGEJO_USERNAME=ci-reader \\
    POETRY_HTTP_BASIC_FORGEJO_PASSWORD="$(cat /run/secrets/forgejo_token)" \\
    poetry install --only main --no-root --no-interaction --no-ansi
'''
NEW = b'''RUN --mount=type=bind,from=a2-inputs,source=index,target=/opt/a2-index,readonly \\
    --mount=type=bind,from=a2-inputs,source=tools,target=/opt/a2-tools,readonly \\
    /opt/poetry/bin/python -I -B /opt/a2-tools/candidate_install.py
'''


def overlay(original):
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256 or original.count(OLD) != 1:
        raise ValueError("original Dockerfile binding/block mismatch")
    before, after = original.split(OLD)
    candidate = before + NEW + after
    if candidate.replace(NEW, OLD, 1) != original or candidate.count(NEW) != 1:
        raise ValueError("overlay changed outside the install instruction")
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dockerfile", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.dockerfile.is_symlink():
        raise ValueError("symlink Dockerfile refused")
    candidate = overlay(args.dockerfile.read_bytes())
    # mkdir is exclusive: an existing destination receives no file actions.
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    (args.out / "Dockerfile.candidate").write_bytes(candidate)
    (args.out / "overlay.json").write_text(json.dumps({
        "original_dockerfile_sha256": ORIGINAL_SHA256,
        "candidate_dockerfile_sha256": hashlib.sha256(candidate).hexdigest(),
        "only_install_instruction_replaced": True,
        "named_local_context": "a2-inputs", "published": False,
        "image_qualified": False,
    }, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
