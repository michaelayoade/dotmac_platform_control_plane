"""Product-owned recovery evidence: the capture query, and the bundle it feeds.

`dotmac-deployment-foundation` owns every recovery DECISION — the role closure,
the completeness refusals, the comparison — and deliberately connects to
nothing, because a facility that could read the database it validates could also
make its own check pass. What belongs here is the product-shaped half: the SQL
that reads this database's catalogue, and the mapping from that reading into the
facility's fact types.

This moved out of `scripts/recovery/` when the CLI was installed as a wheel. The
SQL is package data now rather than a file beside a checkout, so
`dotmac-platform recovery capture-sql` emits the same bytes on a host that has
no repository on it.
"""
