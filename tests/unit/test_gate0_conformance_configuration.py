"""Only the two explicitly selected non-database mechanisms bypass the DB guard."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from conformance.conftest import pytest_configure

ROOT = Path(__file__).resolve().parents[2] / "conformance"
D16 = str(ROOT / "test_d16_source_verifier_real_foundation.py")
ARCHIVE = str(ROOT / "test_gate0_e_archive_gpg.py")


@pytest.mark.parametrize("requested", [[D16], [ARCHIVE], [ARCHIVE + "::test_selected"]])
def test_explicit_non_database_file_keeps_its_own_required_inputs(
    monkeypatch, requested
):
    monkeypatch.delenv("CONFORMANCE_DATABASE_URL", raising=False)
    pytest_configure(SimpleNamespace(args=requested))


@pytest.mark.parametrize(
    "requested", [[], [str(ROOT)], [D16, ARCHIVE], [ARCHIVE, str(ROOT / "database.py")]]
)
def test_directory_mixed_and_other_runs_still_require_database(monkeypatch, requested):
    monkeypatch.delenv("CONFORMANCE_DATABASE_URL", raising=False)
    with pytest.raises(pytest.UsageError, match="CONFORMANCE_DATABASE_URL"):
        pytest_configure(SimpleNamespace(args=requested))


def test_database_configuration_does_not_change_suite_selection(monkeypatch):
    monkeypatch.setenv("CONFORMANCE_DATABASE_URL", "postgresql://synthetic-unused")
    pytest_configure(SimpleNamespace(args=[str(ROOT)]))
