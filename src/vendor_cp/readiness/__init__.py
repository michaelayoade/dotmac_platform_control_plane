"""Whether this process can actually serve, as distinct from being alive.

The kernel owns `/health`, and its docstring is explicit: *"Liveness — does not
touch DB."* That is the correct thing for a liveness probe to be, and this
module does not fork it.

What the deployment needed and did not have is the OTHER question. The
production compose file waits on the application with `up -d app --wait`, and
that wait was satisfied by liveness — so a container whose database was
unreachable reported healthy, `scripts/deploy_production.sh` declared the deploy
successful, and the first request an operator made was the thing that found out.
A deploy that cannot fail at the point of the check is not being checked.

## Why the assembly owns it and the kernel does not

Liveness is generic: every process can answer it, and it means the same thing
everywhere. Readiness is not — it is the question "are MY dependencies
reachable", and only the assembly knows what its dependencies are. This one has
exactly one: the single control-plane database (deny case D1). A kernel-owned
readiness route would either have to guess that, or take a registry of checks
and become a framework for something with one member here.
"""
