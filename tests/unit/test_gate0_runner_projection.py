"""Hosted CI adapter tests; no installed server, campaign, or acceptance claim."""

import base64
import io
import time
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from test_gate0_collection_api import case  # noqa: F401
from test_gate0_window import window_document  # noqa: F401

from vendor_cp.deployment import gate0_runner_projection as client
from vendor_cp.deployment.gate0_framing import canonical, strict_object
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_window import FrozenIssuerWindow


@pytest.fixture
def runner_cases(case):  # noqa: F811
    b = case.configured
    doc = deepcopy(case.window.document)
    doc["case_kind"] = "consume_replay"
    doc["window_id"] = "synthetic-A"
    doc["controller"]["lease_id"] = "synthetic-A-lease"
    doc["controller"]["fingerprint"] = "SHA256:" + base64.b64encode(
        bytes([1]) * 32
    ).decode().rstrip("=")
    doc["controller"]["certificate_digest"] = "sha256:" + "8" * 64
    window = FrozenIssuerWindow.parse(canonical(doc))
    packet = strict_object(b.shared_packet)
    packet["case_kind"] = doc["case_kind"]
    packet["capture"] = dict(
        packet["capture"],
        window_digest=window.digest,
        plan_id=str(UUID(int=10)),
        approval_request_id=str(UUID(int=11)),
    )
    origin = (b.clock.wall_origin, b.clock.monotonic_origin)
    return (
        client.RunnerProjectionCase(canonical(packet), window.canonical_bytes, *origin),
        client.RunnerProjectionCase(b.shared_packet, b.frozen_window, *origin),
    )


def approval_bytes(case, selected):  # noqa: F811
    w, b = selected.window.document, selected.binding
    return canonical(
        dict(
            schema="Gate0CollectionApproval.v1",
            binding=b,
            frozen_window_b64=base64.b64encode(selected.frozen_window).decode(),
            descriptor_digest=w["plan_inputs"]["descriptor_digest"],
            authorized_image_digests=["sha256:" + "6" * 64],
            observed_at=datetime.now(UTC).isoformat(),
            approval=dict(
                request_id=b["approval_request_id"],
                subject_type="rehearsal_issuer_plan.v1",
                subject_id="|".join(
                    [
                        "v1",
                        b["plan_id"],
                        w["purpose"],
                        w["target"]["operation"],
                        w["plan_inputs"]["execution_plan_digest"],
                    ]
                ),
                content_digest=b["plan_digest"],
                policy_code=w["approval_policy"]["code"],
                policy_version=w["approval_policy"]["version"],
                state="approved",
                decided_at=case.decided.isoformat(),
                decisions=[
                    dict(
                        id=str(UUID(int=4)),
                        actor_id=str(UUID(int=5)),
                        action="approve",
                        decided_at=case.decided.isoformat(),
                    )
                ],
            ),
        )
    )


def jwt(exp):
    payload = base64.urlsafe_b64encode(canonical({"exp": exp})).rstrip(b"=").decode()
    return "e30." + payload + ".c2ln"


def test_actual_projection_derives_existing_binding_and_preserves_bytes(
    case,  # noqa: F811
    runner_cases,
):
    selected = runner_cases[1]
    raw = approval_bytes(case, selected)
    parsed = client.decode_approval(raw, selected)
    assert parsed.raw is raw
    assert parsed.binding.expectation.operation.plan_id == selected.binding["plan_id"]
    assert parsed.binding.expectation.operation.operation == "deploy"
    assert parsed.binding.expectation.frozen_window_bytes == selected.frozen_window


@pytest.mark.parametrize(
    "field",
    [
        "launch_packet_digest",
        "case_kind",
        "window_id",
        "window_digest",
        "plan_id",
        "plan_digest",
        "target_id",
        "approval_request_id",
        "run_id",
        "run_attempt",
    ],
)
def test_every_binding_coordinate_is_closed(case, runner_cases, field):  # noqa: F811
    selected = runner_cases[1]
    value = strict_object(approval_bytes(case, selected))
    value["binding"][field] = "foreign"
    with pytest.raises(ProviderRefused):
        client.decode_approval(canonical(value), selected)


@pytest.mark.parametrize(
    "change",
    [
        "unknown",
        "duplicate",
        "noncanonical",
        "oversize",
        "window",
        "subject",
        "policy-bool",
        "future",
        "decision",
        "images",
    ],
)
def test_approval_shape_and_owner_terms_refuse(case, runner_cases, change):  # noqa: F811
    selected = runner_cases[1]
    value = strict_object(approval_bytes(case, selected))
    if change == "unknown":
        value["owner"] = "invented"
    elif change == "window":
        value["frozen_window_b64"] = base64.b64encode(
            runner_cases[0].frozen_window
        ).decode()
    elif change == "subject":
        value["approval"]["subject_id"] = "foreign"
    elif change == "policy-bool":
        value["approval"]["policy_version"] = True
    elif change == "future":
        value["observed_at"] = (datetime.now(UTC) + timedelta(seconds=10)).isoformat()
    elif change == "decision":
        value["approval"]["decisions"][0]["action"] = "reject"
    elif change == "images":
        value["authorized_image_digests"] = []
    raw = canonical(value)
    if change == "duplicate":
        raw = raw[:-1] + b',"schema":"Gate0CollectionApproval.v1"}'
    elif change == "noncanonical":
        raw = b" " + raw
    elif change == "oversize":
        raw += b" " * 65536
    with pytest.raises((ProviderRefused, ValueError)):
        client.decode_approval(raw, selected)


@pytest.mark.parametrize(
    "origin",
    [
        "http://cp.example.invalid",
        "https://user@cp.example.invalid",
        "https://cp.example.invalid:444",
        "https://cp.example.invalid/",
        "https://cp.example.invalid?q=x",
        "https://cp.example.invalid#f",
        "https://127.0.0.1",
        "https://cp.example.invalid\\evil",
        "https://CP.example.invalid",
    ],
)
def test_origin_is_closed_without_claiming_authenticity(runner_cases, origin):
    with pytest.raises((ProviderRefused, ValueError)):
        client.RunnerProjectionClient(origin, runner_cases)


def test_exp_is_only_a_restrictive_cap(runner_cases):
    selected = runner_cases[1]
    now = time.monotonic()
    distant = int((datetime.now(UTC) + timedelta(days=1)).timestamp())
    assert client._jwt_deadline(jwt(distant), selected) <= min(
        selected.deadline, now + 5.1
    )
    expired = int((datetime.now(UTC) - timedelta(seconds=1)).timestamp())
    assert client._jwt_deadline(jwt(expired), selected) < time.monotonic()


class MemorySocket:
    def __init__(self, wire):
        self.stream = io.BytesIO(wire)

    def makefile(self, mode):
        assert mode == "rb"
        return self.stream


def parsed_http(wire):
    response = client._ProjectionHTTPResponse(MemorySocket(wire))
    response.begin()
    return response


def test_exact_get_headers_no_body_proxy_or_redirect(monkeypatch):
    calls, sent = [], []

    class HTTPS:
        def __init__(self, host, port, *, timeout, context):
            calls.append((host, port, timeout, context))

        def request(self, method, path, *, body, headers):
            assert method == "GET" and body is None
            assert path == client._PREFIX + "fixed/withdrawal"
            assert headers == {
                "Authorization": "Bearer private-token",
                "Accept": "application/json",
                "Connection": "close",
                client._REFERENCE: "human-ref",
            }

        def getresponse(self):
            return parsed_http(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 2\r\n\r\n{}"
            )

        def close(self):
            sent.append("closed-http")

    class Pipe:
        def send_bytes(self, raw):
            sent.append(raw)

        def close(self):
            sent.append("closed-pipe")

    monkeypatch.setattr(client.http.client, "HTTPSConnection", HTTPS)
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid")
    monkeypatch.setenv("SSL_CERT_FILE", "/attacker/ca")
    client._read_child(
        Pipe(),
        "cp.example.invalid",
        client._PREFIX + "fixed/withdrawal",
        "private-token",
        "human-ref",
        1,
    )
    assert calls[0][:3] == ("cp.example.invalid", 443, 1)
    assert sent == ["closed-http", b"{}", "closed-pipe"]


@pytest.mark.parametrize(
    "status,body,location",
    [
        (302, b"{}", "https://foreign.invalid"),
        (200, b"x" * 65537, None),
        (200, b"{}", "https://foreign.invalid"),
    ],
)
def test_child_refuses_redirect_and_oversize_without_diagnostics(
    monkeypatch, capsys, status, body, location
):
    sent = []

    wire = (
        f"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n".encode()
    )
    if location is not None:
        wire += f"Location: {location}\r\n".encode()
    wire += b"\r\n" + body

    class HTTPS:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return parsed_http(wire)

        def close(self):
            pass

    class Pipe:
        def send_bytes(self, value):
            sent.append(value)

        def close(self):
            pass

    monkeypatch.setattr(client.http.client, "HTTPSConnection", HTTPS)
    client._read_child(Pipe(), "cp.example.invalid", "/fixed", "secret", None, 1)
    assert not sent
    assert capsys.readouterr() == ("", "")


def test_existing_cancellation_owner_gets_only_fixed_child(monkeypatch):
    def cancel(target, args, deadline):
        assert target is client._read_child
        assert args[:4] == ("cp.example.invalid", "/fixed", "private", None)
        assert 0 < args[4] <= 5
        raise ProviderRefused()

    monkeypatch.setattr(client, "_spawn_request", cancel)
    with pytest.raises(ProviderRefused):
        client._request(
            "cp.example.invalid", "/fixed", "private", None, time.monotonic() + 1
        )


def test_budget_consumes_failed_calls_and_never_retries(runner_cases, monkeypatch):
    calls = []

    def refuse(*args):
        calls.append(args)
        raise ProviderRefused()

    monkeypatch.setattr(client, "_request", refuse)
    cp = client.RunnerProjectionClient("https://cp.example.invalid", runner_cases)
    token = jwt(int((datetime.now(UTC) + timedelta(seconds=30)).timestamp()))
    for selected in runner_cases:
        for _ in range(2):
            with pytest.raises(ProviderRefused):
                cp.approval(selected, token)
    assert len(calls) == 2
    for _ in range(17):
        with pytest.raises(ProviderRefused):
            cp.withdrawal(
                token, reference="human", approval=None, authorization_ref="actual"
            )
    assert len(calls) == 18
    assert all(
        args[1].startswith(client._PREFIX) and "?" not in args[1] for args in calls
    )


def test_withdrawal_event_relay_authorization_join(case, runner_cases):  # noqa: F811
    selected = runner_cases[1]
    approval = client.decode_approval(approval_bytes(case, selected), selected)
    a = strict_object(approval.raw)["approval"]
    event = str(UUID(int=90))
    value = dict(
        schema="Gate0CollectionWithdrawal.v1",
        binding=selected.binding,
        state="applied",
        observed_at=datetime.now(UTC).isoformat(),
        withdrawal=dict(
            request_id=selected.binding["approval_request_id"],
            withdrawal_id=event,
            actor_id=str(UUID(int=91)),
            authority_ref="human-authority",
            approved_at=approval.approved_at.isoformat(),
            effective_at=approval.approved_at.isoformat(),
            external_ref="human-ref",
        ),
        relay=dict(
            event_id=event,
            payload_digest="sha256:" + "9" * 64,
            event_type="approval.withdrawn",
            request_id=selected.binding["approval_request_id"],
            subject_type=a["subject_type"],
            subject_id=a["subject_id"],
            plan_id=selected.binding["plan_id"],
            withdrawal_ref=event,
            disposition="applied",
            authorizations_revoked=["actual-B-authorization"],
        ),
    )
    result = client.decode_withdrawal(
        canonical(value),
        selected,
        reference="human-ref",
        approval=approval,
        authorization_ref="actual-B-authorization",
    )
    assert result.state == "applied" and result.withdrawal_id == event
    for section, key in [
        ("withdrawal", "request_id"),
        ("withdrawal", "external_ref"),
        ("relay", "event_id"),
        ("relay", "withdrawal_ref"),
        ("relay", "plan_id"),
        ("relay", "authorizations_revoked"),
    ]:
        changed = deepcopy(value)
        changed[section][key] = (
            ["foreign"] if key == "authorizations_revoked" else "foreign"
        )
        with pytest.raises(ProviderRefused):
            client.decode_withdrawal(
                canonical(changed),
                selected,
                reference="human-ref",
                approval=approval,
                authorization_ref="actual-B-authorization",
            )


def test_late_transport_result_is_discarded(runner_cases, monkeypatch):
    selected = runner_cases[0]
    cp = client.RunnerProjectionClient("https://cp.example.invalid", runner_cases)
    token = jwt(int((datetime.now(UTC) + timedelta(seconds=30)).timestamp()))
    ticks = [time.monotonic()]
    monkeypatch.setattr(client.time, "monotonic", lambda: ticks[0])

    def late(*args):
        ticks[0] = args[-1] + 0.01
        return b"{}"

    monkeypatch.setattr(client, "_request", late)
    with pytest.raises(ProviderRefused):
        cp.approval(selected, token)


@pytest.mark.parametrize(
    "reference", ["", " spaced", "line\rbreak", "x" * 201, "\u2603"]
)
def test_reference_cannot_inject_headers_or_fall_back_to_query(
    runner_cases, monkeypatch, reference
):
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: pytest.fail("invalid header reached transport"),
    )
    cp = client.RunnerProjectionClient("https://cp.example.invalid", runner_cases)
    with pytest.raises(ProviderRefused):
        cp.withdrawal(
            "token", reference=reference, approval=None, authorization_ref="actual"
        )


def test_pending_withdrawal_cannot_smuggle_relay(case, runner_cases):  # noqa: F811
    selected = runner_cases[1]
    approved = client.decode_approval(approval_bytes(case, selected), selected)
    value = dict(
        schema="Gate0CollectionWithdrawal.v1",
        binding=selected.binding,
        state="pending_withdrawal",
        withdrawal=None,
        relay=None,
        observed_at=datetime.now(UTC).isoformat(),
    )
    assert (
        client.decode_withdrawal(
            canonical(value),
            selected,
            reference="human",
            approval=approved,
            authorization_ref="actual",
        ).state
        == "pending_withdrawal"
    )
    value["relay"] = {}
    with pytest.raises(ProviderRefused):
        client.decode_withdrawal(
            canonical(value),
            selected,
            reference="human",
            approval=approved,
            authorization_ref="actual",
        )


@pytest.mark.parametrize(
    "framing,body",
    [
        (b"Content-Length: 2\r\n", b"{}"),
        (
            b"Transfer-Encoding: chunked\r\n",
            b"2\r\n{}\r\n0\r\nTrailer: bounded\r\n\r\n",
        ),
    ],
)
def test_real_http_parser_valid_framing_and_eof(framing, body):
    response = parsed_http(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + framing
        + b"\r\n"
        + body
    )
    try:
        assert client._decode_response(response) == b"{}"
    finally:
        response.close()


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 200 OK\r\nX-Long: " + b"x" * 16384 + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n"
        + b"X: "
        + b"x" * 9000
        + b"\r\nY: "
        + b"x" * 9000
        + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n2;" + b"x" * 16384 + b"\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\nX: "
        + b"x" * 16384
        + b"\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + b"1;"
        + b"x" * 8000
        + b"\r\n{\r\n1;"
        + b"x" * 8000
        + b"\r\n}\r\n0\r\nX: "
        + b"x" * 1000
        + b"\r\n\r\n",
    ],
)
def test_actual_http_parser_cumulative_lines_are_bounded_before_decode(wire):
    sock = MemorySocket(wire)
    response = client._ProjectionHTTPResponse(sock)
    try:
        with pytest.raises(ProviderRefused):
            response.begin()
            client._decode_response(response)
        # A too-long line consumes at most one byte beyond the shared bound.
        assert sock.stream.tell() <= 16400
    finally:
        response.close()


@pytest.mark.parametrize(
    "framing,body",
    [
        (b"", b"{}"),
        (b"Content-Length: 2\r\nContent-Length: 2\r\n", b"{}"),
        (
            b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
            b"2\r\n{}\r\n0\r\n\r\n",
        ),
        (
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            b"2\r\n{}\r\n0\r\n\r\n",
        ),
        (b"Content-Length: 65537\r\n", b"{}"),
        (b"Content-Length: 3\r\n", b"{}"),
        (b"Content-Length: 2\r\n", b"{}trailing"),
        (b"Transfer-Encoding: chunked\r\n", b"2\r\n{}\r\n0\r\n\r\ntrailing"),
        (
            b"Transfer-Encoding: chunked\r\n",
            b"10001\r\n" + b"x" * 65537 + b"\r\n0\r\n\r\n",
        ),
    ],
)
def test_real_http_parser_ambiguous_truncated_oversize_and_trailing_refuse(
    framing, body
):
    response = parsed_http(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + framing
        + b"\r\n"
        + body
    )
    try:
        with pytest.raises((ProviderRefused, client.http.client.HTTPException)):
            client._decode_response(response)
    finally:
        response.close()


@pytest.mark.parametrize("failure", ["response-close", "connection-close"])
def test_transport_cleanup_failure_suppresses_raw_result(monkeypatch, capsys, failure):
    sent = []
    response = parsed_http(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: 2\r\n\r\n{}"
    )

    def bad_close():
        raise RuntimeError("private credential-bearing cleanup diagnostic")

    if failure == "response-close":
        monkeypatch.setattr(response, "close", bad_close)

    class HTTPS:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return response

        def close(self):
            if failure == "connection-close":
                bad_close()

    class Pipe:
        def send_bytes(self, raw):
            sent.append(raw)

        def close(self):
            pass

    monkeypatch.setattr(client.http.client, "HTTPSConnection", HTTPS)
    client._read_child(Pipe(), "cp.example.invalid", "/fixed", "secret", None, 1)
    assert not sent
    assert capsys.readouterr() == ("", "")
    monkeypatch.undo()
    response.close()


@pytest.mark.parametrize("operation", ["approval", "withdrawal"])
@pytest.mark.parametrize("overrun", [0.0, 0.001])
def test_original_request_deadline_covers_semantic_decoder(
    case,  # noqa: F811
    runner_cases,
    monkeypatch,
    operation,
    overrun,
):
    """A timely HTTP read cannot authorize acceptance at/after its earlier cap."""
    selected = runner_cases[1]
    approval_raw = approval_bytes(case, selected)
    approved = client.decode_approval(approval_raw, selected)
    withdrawal_raw = canonical(
        dict(
            schema="Gate0CollectionWithdrawal.v1",
            binding=selected.binding,
            state="pending_withdrawal",
            withdrawal=None,
            relay=None,
            observed_at=datetime.now(UTC).isoformat(),
        )
    )
    cp = client.RunnerProjectionClient("https://cp.example.invalid", runner_cases)
    ticks = [time.monotonic()]
    request_deadlines = []
    token = jwt(int((datetime.now(UTC) + timedelta(seconds=30)).timestamp()))
    monkeypatch.setattr(client.time, "monotonic", lambda: ticks[0])

    def timely_transport(*args):
        request_deadlines.append(args[-1])
        return approval_raw if operation == "approval" else withdrawal_raw

    decoder_name = "decode_" + operation
    original_decoder = getattr(client, decoder_name)

    def decoder_crosses_original_cap(*args, **kwargs):
        # Run real semantic validation while both clocks still permit it.
        result = original_decoder(*args, **kwargs)
        ticks[0] = request_deadlines[0] + overrun
        assert selected.start <= ticks[0] < selected.deadline
        return result

    monkeypatch.setattr(client, "_request", timely_transport)
    monkeypatch.setattr(client, decoder_name, decoder_crosses_original_cap)
    with pytest.raises(ProviderRefused):
        if operation == "approval":
            cp.approval(selected, token)
        else:
            cp.withdrawal(
                token,
                reference="human",
                approval=approved,
                authorization_ref="actual-B-authorization",
            )
    assert len(request_deadlines) == 1
