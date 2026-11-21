#!/usr/bin/env python3
"""Refuse PRODUCTION-IMAGE PUBLICATION while the vendored Foundation pin is provisional.

`src/vendor_cp/vendored_foundation/PINS.json` records Foundation source copied before
E5 is certified (status `PROVISIONAL-PENDING-E5`). That is acceptable for the
unpublished PR-head image dry runs use and for ordinary CI, and it must never reach
a published production image. This runs only on the publication path
(`production-image.yml`), never in `ci.yml`.

It admits only `status == "CERTIFIED"` together with an `e5_record_digest` of the
form `sha256:<64 lower-case hex>` (the digest of Michael's E5 certification record).
Exit 0 admits; non-zero refuses, with the reason. Standard library only, no network.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

DEFAULT = Path("src/vendor_cp/vendored_foundation/PINS.json")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def problems(pins: object) -> list[str]:
    if not isinstance(pins, dict):
        return ["the vendored Foundation pin file is not a JSON object"]
    found: list[str] = []
    if pins.get("status") != "CERTIFIED":
        found.append(
            f"vendored Foundation pin status is {pins.get('status')!r}, not "
            "'CERTIFIED': E5 has not certified this source"
        )
    digest = pins.get("e5_record_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        found.append("vendored Foundation pin carries no valid e5_record_digest")
    return found


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT
    try:
        pins = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"refused: {path} unreadable: {error}", file=sys.stderr)
        return 2
    reasons = problems(pins)
    for reason in reasons:
        print(f"refused: {reason}", file=sys.stderr)
    if not reasons:
        print("vendored Foundation pin is CERTIFIED with an E5 record digest")
    return 1 if reasons else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
