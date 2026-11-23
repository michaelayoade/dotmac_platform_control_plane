# Dispatch recovery source qualification

This explicitly invoked offline suite requires the new public Control recovery
API from the reviewed sibling source checkout. CP's release pin remains Control
a17; normal issuance does not forward the new keyword to that installed API.
These tests do not establish installed artifact, migration, PostgreSQL locking,
OpenBao role/policy enforcement or native recovery qualification.

From the CP worktree, the source-only qualification environment used on
2026-11-23 was:

```sh
PYTHONPATH=src:$CONTROL_SRC:$VENV/lib/python3.12/site-packages:$KERNEL_SRC \
../control/.venv-recovery-tests/bin/python -m pytest --noconftest \
  conformance/recovery_source/test_contract.py \
  tests/unit/test_foundation_execution_approval.py -q
```

The environment supplies its actual distribution metadata; the suite does not
change a published version or supply a runtime import shim. Normal unit doubles
live in `tests/unit/test_target_materials_producer.py` and
`tests/unit/test_target_transit_custody.py`. Their CLI tests need an installed
kernel audit registry, normally supplied by the repository conftest. The
focused standalone qualification installs an empty in-process registry before
pytest because it deliberately excludes the composed application conftest; it
therefore makes no application bootstrap claim.
