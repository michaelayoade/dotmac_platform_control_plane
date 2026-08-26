#!/usr/bin/env python
"""Print aggregate, read-only commercial-shadow readiness evidence as JSON."""

from __future__ import annotations

import json

from dotmac_kernel.db import platform_session

from vendor_cp.commercial_shadow_readiness import (
    observe_commercial_shadow_readiness,
)


def main() -> int:
    with platform_session() as db:
        report = observe_commercial_shadow_readiness(db)
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
