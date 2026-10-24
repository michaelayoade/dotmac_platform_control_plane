"""Deploy-only transition refusal, with a real Alembic dependency graph."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from alembic.config import Config

from vendor_cp import migrations
from vendor_cp.cli import main

BARRIER = migrations.DEPLOYMENT_CONTROL_BARRIER


@pytest.fixture
def graph(tmp_path: Path) -> Config:
    versions = tmp_path / "versions"
    versions.mkdir()
    # Lexical ordering deliberately disagrees with ancestry. The last head's
    # only connection to the barrier is depends_on, not down_revision.
    for revision, parent, dependency in (
        ("zz_before", None, None),
        (BARRIER, "zz_before", None),
        ("aa_after", None, BARRIER),
        ("ab_after_lineage", BARRIER, None),
    ):
        (versions / f"{revision}.py").write_text(
            f"revision = {revision!r}\ndown_revision = {parent!r}\n"
            f"depends_on = {dependency!r}\nbranch_labels = None\n"
        )
    config = Config()
    config.set_main_option("script_location", str(tmp_path))
    return config


def _check(
    monkeypatch: pytest.MonkeyPatch,
    config: Config,
    heads: tuple[str, ...],
    *,
    populated: bool = False,
) -> Mock:
    connection = Mock()
    connection.dialect = SimpleNamespace(name="postgresql")
    monkeypatch.setattr(migrations, "_source_heads", lambda connection: heads)
    catalog = Mock(return_value=populated)
    monkeypatch.setattr(migrations, "_has_data_bearing_relations", catalog)
    migrations.require_deploy_transition(connection, config)
    return catalog


@pytest.mark.parametrize("heads", [(BARRIER,), ("aa_after",), ("ab_after_lineage",)])
def test_barrier_or_dependency_descendant_proceeds(
    monkeypatch: pytest.MonkeyPatch, graph: Config, heads: tuple[str, ...]
) -> None:
    catalog = _check(monkeypatch, graph, heads, populated=True)
    catalog.assert_not_called()


@pytest.mark.parametrize(
    "heads",
    [
        ("zz_before",),
        ("not_installed",),
        ("aa_a",),  # Alembic's partial identifier is not a canonical version row.
        ("heads",),
        ("",),
        (BARRIER, BARRIER),
        (BARRIER, "zz_before"),
        ("aa_after", "not_installed"),
    ],
)
def test_old_unknown_or_malformed_heads_refuse(
    monkeypatch: pytest.MonkeyPatch, graph: Config, heads: tuple[str, ...]
) -> None:
    with pytest.raises(migrations.MigrationTransitionRefused):
        _check(monkeypatch, graph, heads)


def test_graph_dependency_labels_resolve_but_recorded_labels_refuse(
    monkeypatch: pytest.MonkeyPatch, graph: Config
) -> None:
    versions = Path(graph.get_main_option("script_location")) / "versions"
    barrier = versions / f"{BARRIER}.py"
    barrier.write_text(
        barrier.read_text().replace(
            "branch_labels = None", "branch_labels = ('barrier_branch',)"
        )
    )
    descendant = versions / "aa_after.py"
    descendant.write_text(
        descendant.read_text().replace(repr(BARRIER), repr("barrier_branch"))
    )
    _check(monkeypatch, graph, ("aa_after",), populated=True)
    with pytest.raises(migrations.MigrationTransitionRefused):
        _check(monkeypatch, graph, ("barrier_branch",), populated=True)


def test_empty_version_rows_require_empty_live_catalog(
    monkeypatch: pytest.MonkeyPatch, graph: Config
) -> None:
    _check(monkeypatch, graph, ()).assert_called_once()
    with pytest.raises(migrations.MigrationTransitionRefused, match="user relations"):
        _check(monkeypatch, graph, (), populated=True)


def test_target_missing_barrier_refuses_even_on_empty_database(
    monkeypatch: pytest.MonkeyPatch, graph: Config
) -> None:
    versions = Path(graph.get_main_option("script_location")) / "versions"
    (versions / f"{BARRIER}.py").unlink()
    (versions / "aa_after.py").unlink()
    (versions / "ab_after_lineage.py").unlink()
    with pytest.raises(migrations.MigrationTransitionRefused, match="target graph"):
        _check(monkeypatch, graph, ())


def test_unreadable_catalog_refuses(
    monkeypatch: pytest.MonkeyPatch, graph: Config
) -> None:
    from sqlalchemy.exc import SQLAlchemyError

    monkeypatch.setattr(migrations, "_source_heads", lambda connection: ())
    monkeypatch.setattr(
        migrations,
        "_has_data_bearing_relations",
        Mock(side_effect=SQLAlchemyError("unreadable catalogue")),
    )
    connection = Mock()
    connection.dialect.name = "postgresql"
    with pytest.raises(
        migrations.MigrationTransitionRefused, match="could not be verified"
    ):
        migrations.require_deploy_transition(connection, graph)


def test_cli_carries_typed_owner_refusal_as_code_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from alembic import command

    monkeypatch.setenv("MIGRATION_DATABASE_URL", "postgresql://unused/unused")
    monkeypatch.setattr(migrations, "deploy_config", lambda url: Config())
    upgrade = Mock(side_effect=migrations.MigrationTransitionRefused("protected HOLD"))
    monkeypatch.setattr(command, "upgrade", upgrade)
    assert main(["--format", "json", "admin", "migrate"]) == 3
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["refusal_code"] == "owner.migration_transition_refused"
    upgrade.assert_called_once()


def test_deploy_config_marks_guard_but_rehearsal_config_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(migrations, "make_alembic_config", lambda url: Config())
    assert migrations.deploy_config("unused").attributes["require_composed_heads"]
    assert not migrations.make_alembic_config("unused").attributes
