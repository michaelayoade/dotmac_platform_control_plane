"""Who this assembly is, read from installed distribution metadata.

## Why there is no version literal in this repository any more

`src/vendor_cp/__init__.py` used to carry `__version__ = "0.1.0"`. Nothing read
it, which is the only reason it never lied — the same shape, in
`dotmac-deployment-control`, did: the published `0.1.0a4` wheel carried
`__version__ = "0.1.0a2"` beside a `pyproject.toml` that said `0.1.0a4`, and any
controller fingerprint reading the attribute would have written the wrong
version into the authorization it exists to make auditable. The bytes were
correct; the self-report was not.

A second copy of a version is a second thing to forget. So there is one copy, in
`pyproject.toml`, and everything that needs the number at runtime reads what the
INSTALLER recorded — which is the only value that describes the artifact
actually running.

## `None` is an answer

`installed_version` returns `None` for a distribution that is not installed
rather than a placeholder. A caller that merely reports prints the absence,
which is useful; a caller that is about to write the value into a receipt calls
`require_version` and refuses. What neither does is invent a number.

## The names are frozen

The repository is Platform Control Plane. The DISTRIBUTION is
`dotmac-vendor-control-plane`, the import package is `vendor_cp`, and the image,
Compose project, database and migration lineage are all still `vendor`. That is
deliberate rather than debt: repository identity changed and artifact identity
was frozen, so a lookup for `dotmac-platform-control-plane` here would ask for a
package nobody publishes.
"""

from __future__ import annotations

from importlib import metadata
from typing import Final

#: This assembly's published distribution name. Frozen — see the docstring.
DISTRIBUTION: Final[str] = "dotmac-vendor-control-plane"

#: The deployment-authorization owner this assembly composes. Named separately
#: from the rest because an authorization receipt binds its version explicitly.
AUTHORITY_DISTRIBUTION: Final[str] = "dotmac-deployment-control"

#: Every separately released owner composed here, in the order a diagnosis
#: should print them: the kernel first, then the modules that depend on it.
COMPOSED_DISTRIBUTIONS: Final[tuple[str, ...]] = (
    "dotmac-kernel",
    AUTHORITY_DISTRIBUTION,
    "dotmac-approvals",
    "dotmac-entitlement-allocation",
    "dotmac-commercial-agreements",
    "dotmac-licensing",
    "dotmac-release-catalog",
)


def installed_version(distribution: str) -> str | None:
    """The version the installer recorded, or `None` when it is not installed."""
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


class NotInstalledError(RuntimeError):
    """This code is running from somewhere that has no distribution metadata.

    Raised rather than defaulted. Running from a checkout is exactly the state a
    hardcoded literal would have papered over, and a receipt that records a
    version nobody can resolve back to an artifact is worse than one that was
    never written.
    """


def require_version(distribution: str = DISTRIBUTION) -> str:
    """The installed version, or refuse to guess one."""
    version = installed_version(distribution)
    if version is None:
        raise NotInstalledError(
            f"{distribution} has no installed distribution metadata, so its "
            "version cannot be reported. Install the wheel; do not run from a "
            "checkout."
        )
    return version


def authority_version() -> str:
    """The composed authorization owner's installed version."""
    return require_version(AUTHORITY_DISTRIBUTION)


__all__ = [
    "AUTHORITY_DISTRIBUTION",
    "COMPOSED_DISTRIBUTIONS",
    "DISTRIBUTION",
    "NotInstalledError",
    "authority_version",
    "installed_version",
    "require_version",
]
