"""The ONE target API: consumption (DESIGN-rev3 section 2.6.1) and, in lane 5c, lease.

Router `/platform/deploy/target/v1`, called by the deploy agent and by the CP
bindings running on a target. The server is written over an abstract
authenticated principal (`auth.TargetPrincipal`), so a later launcher client
only needs a principal to be enrolled, not a new endpoint.

This package is NOT composed into any deployment profile by lane 5b: the M4
profile that mounts it is lane 5a's. Nothing here is reachable from a running
assembly until then.
"""
