# Gate-0 envelope source conformance

These source-only synthetic and mocked suites are configured as two separate,
non-root unittest discovery processes in the existing hosted CI `check` job.
Native discovery runs both `test_adapter.py` and `test_outer.py` in the same
process. Activation runs in its own process. Neither loads pytest's conformance
database fixtures; sibling imports and template lookups stay within each subtree.
The existing ordinary test suite is unchanged.

The suites check source behavior, including refusals and fixed vectors. A
passing run does not establish native timing, installation, host eligibility,
tracer behavior, retirement, or qualification. Native boundaries are mocked;
no private inputs, proof captures, host configuration, or execution selectors
are included. These files are outside the installed production package. No
native qualification workflow is added.

Origins are the frozen activation-source-r3 and reviewed
native-envelope-adapter-source-r4 candidates. Activation freeze SHA-256:
`b97c0c96695358fc6b4defade56481038409fdba59892be4834b126921af7c16`.
Native R4 freeze manifest SHA-256:
`f4321913e6a38d545c8143065d9a80603a74331bdf7e3649cb2a635a93bac6f6`.
Independent R4 review SHA-256:
`54ad3028dab4cc1e462c727c13ab541cd92a6c413128bb2043a5c6cf9b493084`,
with verdict `PASS_SOURCE_REVIEW`. That verdict closes reviewed source defects
only; native execution and qualification remain **UNRUN**.

The freezes remain unchanged. Native integration copies contain only five
Python files and seven template fragments. They use repository formatting,
sorted imports, and removal of redundant read modes. One synchronous mocked
test captures its per-case iterator explicitly in a lambda default. Narrow
inline lint annotations explain fixed execution vectors and mocked reads.
Other Python AST semantics, fixed vectors, refusal conditions, and template
bytes remain intact. Activation integration normalizations are unchanged.
This integration was validated statically with AST/hash checks and pinned Ruff
0.6.9; the mocked suites were **UNRUN** during integration.

Hosted CI is configured with these commands, each in its own process:

```sh
python -m unittest discover -s conformance/gate0_envelope_source/activation -p test_candidate_source.py -v
python -m unittest discover -s conformance/gate0_envelope_source/native -p 'test_*.py' -v
```
