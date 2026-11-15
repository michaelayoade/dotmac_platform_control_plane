"""Standalone, read-only check of the scoped consumption role (R5).

The startup proof inside `bindings()` runs on the target and so cannot bound a
compromised target. This command runs the SAME proof independently, from the
ceremony or launcher, BEFORE the credential is handed over, and its result is
recorded as ceremony evidence. It opens one read-only transaction, runs
catalogue queries only, and prints a single line naming a typed code, never a
value.

    # about the credential itself (the DSN the target will receive):
    DISPATCH_CONSUMPTION_DATABASE_URL=... \\
        python -m vendor_cp.deployment.consumption_role_check

    # about a named role, over an administrative read-only connection:
    CONSUMPTION_ROLE_CHECK_DATABASE_URL=... \\
        python -m vendor_cp.deployment.consumption_role_check --role NAME

Exit 0 only when the role is proven; 2 on any refusal.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Final

from vendor_cp.deployment.consumption_scope import (
    consumption_sessions,
    prove_scoped_role,
    scoped_consumption_dsn,
)
from vendor_cp.deployment.target_refusals import (
    FoundationBindingsUnavailable,
    TargetRefusal,
)

ADMIN_DSN_ENV: Final = "CONSUMPTION_ROLE_CHECK_DATABASE_URL"


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", default=None)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        if args.role is None:
            dsn = scoped_consumption_dsn(env)
        else:
            dsn = env.get(ADMIN_DSN_ENV, "").strip()
            if not dsn:
                raise FoundationBindingsUnavailable(
                    f"{ADMIN_DSN_ENV} is not supplied",
                    code=TargetRefusal.CONSUMPTION_DSN_MISSING,
                )
        prove_scoped_role(consumption_sessions(dsn), role=args.role)
    except FoundationBindingsUnavailable as refusal:
        print(
            f"consumption role check refused: {refusal.code}: {refusal}",
            file=sys.stderr,
        )
        return 2
    print("consumption role check passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
