# A9 closed CP projection adapter

`gate0_runner_projection.py` is source-only. It does not install or activate the
collector, approve a campaign, authenticate installation files, or select an
actual CP hostname. The protected runner installer must bind the real HTTPS
origin and exact A/B packets/frozen windows to its authenticated installation.
Construction checks their shape and agreement only.

The client has two fixed GET projections for those installed window IDs. It
sends the job JWT as `Authorization: Bearer` and the bounded human withdrawal
reference as `X-Dotmac-Gate0-Withdrawal-Reference`. It sends no request body or
query, follows no redirects, uses no proxy environment, retries nothing, and
never accesses a CP database or custody HTTP transport. TLS uses compiled
system CA paths, with hostname verification and certificate verification;
`SSL_CERT_FILE` and `SSL_CERT_DIR` cannot override them. A deployment whose
compiled system CA paths are unavailable refuses and needs a separately
reviewed installed trust binding; this source does not guess one.

Each request uses the existing CP-local `_spawn_request` cancellation owner,
unchanged. A new fixed child owns only HTTPS GET and the exact Bearer/reference
headers. The parent deadline includes DNS, TLS, HTTP headers/body, IPC and child
termination and semantic DTO decoding through final public return: the minimum of the original protected interval, the JWT payload's
restrictive expiry cap and five seconds. Parsing `exp` is not signature
verification and cannot extend the original interval. The authenticated CP
server retains the sole signature and exact frozen workload scope check.
The exact request deadline computed before transport is retained through decoding
and checked immediately before returning either projection; decoding cannot
refresh the five-second or JWT cap. Equality with the deadline refuses.
Before HTTP parsing, the narrow response subclass wraps the socket using the
existing unchanged CP `_BoundedHTTPSocket` / `_BoundedHTTPReader`. Their 16384-byte
cumulative line budget includes status/header lines, chunk extensions and
trailers. Framing requires exactly one Content-Length or exactly one chunked
Transfer-Encoding, never both or duplicates. Declared and actual bodies stay
within 65536 bytes; actual framed completion and stream EOF are required. The
response and HTTPS connection must close successfully before bytes enter IPC.
Canonical JSON response bytes are preserved exactly,
with a 65536-byte limit and duplicate/unknown fields refused.

The client owns one serialized A/B read budget: one approval read per case and
at most sixteen B withdrawal reads, including failed transport attempts. It has
no automatic polling or campaign loop. Calling the pure DTO parsers separately
does not authenticate their input; production callers must obtain their bytes
through the configured client's authenticated TLS read.

Approval decoding checks the shared packet, frozen window, all ten response
binding fields, actual owner policy/subject/content/decision terms, descriptor
and image digests. It derives the existing `AdmittedOperation`,
`AdmissionExpectation` and `ApprovedWindowBinding` from those terms without a
fabricated plan or database session. This is approved-at-read evidence; it is
neither a transferable hold nor root capture delivery. Withdrawal decoding
joins the original approval timestamp/request, human reference, immutable event
UUID and exact applied relay row to the supplied actual issued B authorization
reference. Its caller must obtain that reference from verified issuer output.

Hosted CI tests cover closed origin/header/path behavior, credential-free
failure, deadline/cancellation delegation, size/canonical/DTO refusals, finite
budgets and event/relay/authorization swaps. No local application imports,
tests, network campaign, custody operation or installation qualify this source
as Gate0 acceptance. Installed entrypoint, root handoff, public trust inputs and
the separately authorized protected campaign remain outside this adapter.
