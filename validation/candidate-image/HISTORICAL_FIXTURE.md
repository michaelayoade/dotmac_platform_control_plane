# Rebuilt historical validation input — preparation only

This separate adapter installs the immutable historical CP source
`348c31315efaaca9ea23ea7c025d137a3afaad74` for the synthetic OLD image required
by `.github/candidate/build_native_source_fixture.sh`. It is a rebuilt validation
input, not previously accepted image bytes, production continuity, a release image
or normal protected-producer provenance. No image has been built or qualified by
this source preparation. Control a17 here and Control a18 in the separate frozen
candidate helper are distinct profiles; neither helper replaces the other.

The coordinator owns the source archive from that exact commit, native fixture
data, the descriptor retained verbatim from the canonical fixture construction,
and its scoped Git bundle. `native-source-descriptor.toml` must remain the verbatim
`348c31315efaaca9ea23ea7c025d137a3afaad74:deploy/product.toml` bytes, never
rewritten as observed build facts. The canonical `native-source.bundle` carries
`refs/heads/source-fixture` at that immutable revision and its reachable history,
from a fresh bare repository with no checkout credentials, hooks or remotes.
Retain that bundle scope; neither the archive nor this adapter
authorizes inventing a production descriptor, widening bundle scope, or claiming
an accepted release. Bind archive, descriptor, bundle and resulting fixture
digests in the coordinator's validation metadata.

The historical Dockerfile has the same original SHA256
`6e8d895d0aece83391c6198e3766d9b2bcfcde79c5874b9398b201c970823340`.
The unchanged `prepare_overlay.py` accepts it and replaces only its known Poetry
install instruction. The overlay is byte-identical to the current candidate
overlay, including the retained AMD64 assertion and GitHub CLI checksum; the
different bound local inputs select the historical installation. No platform
assertion, base, assembly wheel build, installed profile, migration heads or
runtime instruction changes.

Stage a separate named local context `a2-inputs` with readonly `index/` and
`tools/`. Mount this reviewed `historical_fixture_install.py` as
`tools/candidate_install.py`, because the unchanged overlay invokes that filename.
Metadata must explicitly identify the historical helper SHA/profile and rebuilt
historical source revision. It must never identify these bytes as frozen current
helper `f12b3709374dfd572e55fc60f35bdc0df3d6cb788f524bae78a86f360b191d9f`.
Also stage the unchanged EF80 owner as `tools/kernel_lock.py` and exact config:

```json
{
  "manifest_sha256": "06f21ab12967c387af5f9792530cfc66c7b590cfeedd75ff6e1450dcfd7f75db",
  "lock_sha256": "92a147efe3c1cd5c7997d2eb5e982342b40ac3e0e604e1d4837829f8fc0a9301",
  "owner_sha256": "ef80e927e1aefba218ec528ac165d2b2c590645dfa9ab1f24b080e2b186ed27d",
  "index_files": {"RELATIVE_INDEX_FILE": "SHA256"}
}
```

`index_files` binds exactly 21 files: the original 14 accepted baseline artifacts
and seven baseline HTML package pages. Every artifact filename/hash is checked
against the old lock, and the page paths must match its seven private packages.
No candidate lane, extra index, credential, new acquisition or arbitrary command
is accepted. Keep all private wheel/index bytes out of Git and CI.

The old lock has 54 packages, Kernel a100 and Control a17. Control's wheel SHA is
`ecd3478a5398ce7c93d1c7195edf76ca4b4630f9c8474527e914d1561a3f39f9` and
its sdist SHA is
`52f2d1f07f6a8aea59fd59eb0c03c6f11973921b9dd5055d9aa84a8c1dd2196a`.
All seven private lock sources and the single explicit Forgejo manifest source
temporarily point to `http://127.0.0.1:8899/baseline/simple`. Whole parsed
transforms are checked, the unchanged owner computes the temporary content hash,
and both original old-pair bytes/hashes are restored in `finally` before the
canonical old wheel build and installed profile run.

Installation preserves the frozen isolation pattern: `/opt/poetry/bin/python
-I -B`, hash-pinned EF80 before compilation, no candidate sys.path or pyc, fresh
HOME/config/data/cache, credential-shaped environment and netrc refusal, app
venv `/opt/venv`, disabled keyring/plugins, binary-only, re-resolve=false and
`install --only main --no-root --no-interaction --no-ansi`. There is no `poetry
lock`, private remote fallback, secret mount or upload. Public locked dependencies
may come from public PyPI. The loopback readonly server stops after installation;
failure exits nonzero without a success result. Success labels
`HISTORICAL_FIXTURE_DEPENDENCIES_INSTALLED`, `rebuilt_validation_input: true`,
`prior_accepted_image_continuity: false`, `published: false` and
`normal_producer_provenance: false`.

The coordinator supplies read-only data fixtures under
`image/fixtures/historical-pair/{pyproject.toml,poetry.lock}` from exact source
348c, alongside existing current `fixtures/pair/` and `Dockerfile.original`.
The separate tests cover historical pair/source/hash guards, current a18 refusal,
21-file closure and lock bindings, all-seven URL transform, exact restoration on
injected install error, overlay identity and the existing isolation/argv checks.
Only AST/static checks were performed by this preparing agent. No tests, target
imports, Poetry, server, network, daemon, build or operational actions were run.
The coordinator reviews and qualifies source through authorized CI before
preparing contexts. An actual AMD64 target remains dependent on user capacity.
