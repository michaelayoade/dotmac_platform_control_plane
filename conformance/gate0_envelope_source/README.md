# Gate-0 envelope source conformance

These source-only synthetic and mocked suites run as two separate, non-root
unittest discovery processes in the existing hosted CI `check` job. They do
not load pytest's conformance database fixtures. Sibling module imports and
activation template lookups stay within each subtree.

The suites check source behavior, including refusals and fixed vectors. A
passing run does not establish native timing, installation, host eligibility,
tracer behavior, retirement, or qualification. Native boundaries are mocked;
no private inputs, proof captures, host configuration, or execution selectors
are included. These files are outside the installed production package.

Origins are the frozen activation-source-r3 and native-envelope-adapter-source-r2
candidates. Activation freeze SHA-256:
`b97c0c96695358fc6b4defade56481038409fdba59892be4834b126921af7c16`.
Native adapter freeze SHA-256:
`6425579d5cabc14f3b1a92bb78dbe83dc59067262745b1dbf94e0269997dbc5b`.
The original freezes remain unchanged. Integration copies use repository
formatting, sorted imports, removal of an unused `stat` import and redundant
read modes, and an unused loop-variable rename. One synchronous mocked test
captures its per-case iterator explicitly in a lambda default. Fixed vectors,
refusal conditions and template bytes remain intact. Narrow inline lint
annotations explain fixed OCI metadata and mocked execution boundaries.

Hosted CI uses exactly these commands, each in its own process:

```sh
python -m unittest discover -s conformance/gate0_envelope_source/activation -p test_candidate_source.py -v
python -m unittest discover -s conformance/gate0_envelope_source/native -p test_adapter.py -v
```
