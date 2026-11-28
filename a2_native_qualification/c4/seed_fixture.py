"""CI-only signer fixture; never add a checkout to the production import path."""

from hashlib import sha256
from pathlib import Path
from types import ModuleType

# tests/authorization_support.py at Control 574418944d35ddf3559d17e59e9184b5f545ebe4.
FIXTURE_SHA256 = "55bfd016d2b01b8ed6cc01d2ebf06ab4b8dfc00d0b34c864316932585efdaf2c"


def load_signer(path: str):
    source = Path(path).read_bytes()
    if sha256(source).hexdigest() != FIXTURE_SHA256:
        raise ValueError("seed_fixture_digest")
    fixture = ModuleType("a2_ci_authorization_fixture")
    # Execute only the captured, verified bytes. Imports resolve the installed
    # Control package; this does not expose the source checkout on sys.path.
    exec(compile(source, "<pinned-ci-signer-fixture>", "exec"), fixture.__dict__)  # noqa: S102 -- exact pinned CI fixture, captured above
    return fixture.SIGNER
