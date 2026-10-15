"""Finite OIDC adapter fixtures, never broker or signature acceptance evidence."""

# ruff: noqa: F811 -- pytest injects imported fixture names.

import base64
import time
from types import SimpleNamespace

import pytest
from test_gate0_runner_installation import (  # noqa: F401
    installed_model,
    window_document,
)

from vendor_cp.deployment import gate0_runner_tokens as tokens
from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_role_custody import ProviderRefused
from vendor_cp.deployment.gate0_runner_installation import InstalledRunnerCollection


@pytest.fixture
def broker():
    return tokens.JobBrokerBinding(
        "https://broker.example",
        "/job/123/token",
        "api-version=2&job=123",
        "sha256:" + "1" * 64,
    )


def test_request_is_exact_and_adds_only_fixed_audience(broker):
    host, path = broker.request_path(
        "https://broker.example/job/123/token?api-version=2&job=123"
    )
    assert host == "broker.example"
    assert path.endswith("&audience=urn%3Adotmac%3Agate0%3Arehearsal-issuer")


@pytest.mark.parametrize(
    "url",
    [
        "http://broker.example/job/123/token?api-version=2&job=123",
        "https://broker.example.attacker/job/123/token?api-version=2&job=123",
        "https://broker.example/job/124/token?api-version=2&job=123",
        "https://broker.example/job/123/token?job=123&api-version=2",
        "https://broker.example/job/123/token?api-version=2&job=123&audience=other",
        "https://broker.example/job/123/token?api-version=2&job=123#extra",
    ],
)
def test_runtime_origin_path_query_are_independently_exact(broker, url):
    with pytest.raises(ProviderRefused):
        broker.request_path(url)


def cases(installed_model):
    return tuple(
        case.projection for case in InstalledRunnerCollection.from_installed().cases
    )


def response(case, overrides=None):
    now = int(time.time())
    claims = dict(case.window.document["github"], iat=now, nbf=now, exp=now + 60)
    claims.update(overrides or {})
    payload = base64.urlsafe_b64encode(canonical(claims)).rstrip(b"=").decode()
    return canonical({"value": "e30." + payload + ".c2ln"})


def test_owned_spawn_has_original_case_five_second_deadline_and_31_slots(
    monkeypatch, installed_model
):
    selected = cases(installed_model)
    source = tokens.InstalledJobTokens(selected, "broker.example", "/fixed", "secret")
    requests = []
    # Isolate only the finite per-phase budget: real disjoint cases cannot both
    # be open at once. The loader test checks original A/B timing separately.
    monkeypatch.setattr(tokens.RunnerProjectionCase, "require_open", lambda _: None)

    def request(target, arguments, deadline):
        assert target is tokens._token_child
        assert deadline <= selected[0].deadline
        assert 0 < deadline - time.monotonic() <= 5
        requests.append(arguments)
        return response(selected[0])

    monkeypatch.setattr(tokens, "_spawn_request", request)
    for case, count in zip(selected, (8, 23), strict=True):
        for _ in range(count):
            assert source.next(case).startswith("e30.")
    assert len(requests) == 31
    with pytest.raises(ProviderRefused):
        source.next(selected[1])


@pytest.mark.parametrize(
    "raw", [b"{}", b'{"value":"a.b.c","extra":true}', b"x" * 65537]
)
def test_failure_is_terminal_and_consumes_attempt(monkeypatch, installed_model, raw):
    selected = cases(installed_model)
    source = tokens.InstalledJobTokens(selected, "broker.example", "/fixed", "secret")
    monkeypatch.setattr(tokens, "_spawn_request", lambda *_: raw)
    with pytest.raises(ProviderRefused):
        source.next(selected[0])
    assert source._counts == [1, 0]
    assert source._credential == ""
    with pytest.raises(ProviderRefused):
        source.next(selected[1])
    assert source._counts == [1, 0]


def test_expired_case_never_spawns(monkeypatch, installed_model):
    selected = cases(installed_model)
    monkeypatch.setattr(
        tokens.RunnerProjectionCase,
        "require_open",
        lambda _: (_ for _ in ()).throw(ProviderRefused()),
    )
    source = tokens.InstalledJobTokens(selected, "broker.example", "/fixed", "secret")
    monkeypatch.setattr(
        tokens, "_spawn_request", lambda *_: pytest.fail("spawn expired")
    )
    with pytest.raises(ProviderRefused):
        source.next(selected[0])


@pytest.mark.parametrize("fail_cleanup", [False, True])
def test_child_exact_get_no_redirect_or_environment_and_cleanup_before_result(
    monkeypatch, installed_model, fail_cleanup
):
    selected = cases(installed_model)
    sent, requests, closed = [], [], []

    class Response:
        def close(self):
            closed.append("response")
            if fail_cleanup:
                raise OSError("private transport details")

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            assert (host, port, timeout) == ("broker.example", 443, 1.0)

        def request(self, method, path, *, body, headers):
            requests.append((method, path, body, headers))

        def getresponse(self):
            return Response()

        def close(self):
            closed.append("connection")

    class Pipe:
        def send_bytes(self, raw):
            assert closed == ["response", "connection"]
            sent.append(raw)

        def close(self):
            closed.append("pipe")

    class Context:
        def load_verify_locations(self, *, cafile, capath):
            assert (cafile, capath) == ("compiled-file", "compiled-dir")

    monkeypatch.setenv("HTTPS_PROXY", "https://attacker.invalid")
    monkeypatch.setenv("SSL_CERT_FILE", "/attacker")
    monkeypatch.setattr(
        tokens.ssl,
        "get_default_verify_paths",
        lambda: SimpleNamespace(
            openssl_cafile="compiled-file", openssl_capath="compiled-dir"
        ),
    )
    monkeypatch.setattr(tokens.ssl, "SSLContext", lambda _: Context())
    monkeypatch.setattr(tokens.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(tokens, "_ProjectionHTTPResponse", Response)
    monkeypatch.setattr(tokens, "_decode_response", lambda _: response(selected[0]))
    tokens._token_child(Pipe(), "broker.example", "/exact", "credential", 1.0)
    assert requests == [
        (
            "GET",
            "/exact",
            None,
            {
                "Authorization": "Bearer credential",
                "Accept": "application/json",
                "Connection": "close",
            },
        )
    ]
    assert len(sent) == (0 if fail_cleanup else 1)
    assert closed == ["response", "connection", "pipe"]


def test_owned_spawn_timeout_is_terminal_without_another_attempt(
    monkeypatch, installed_model
):
    selected = cases(installed_model)
    source = tokens.InstalledJobTokens(selected, "broker.example", "/fixed", "secret")
    calls = []

    def timeout(*_):
        calls.append(1)
        raise ProviderRefused()

    monkeypatch.setattr(tokens, "_spawn_request", timeout)
    with pytest.raises(ProviderRefused):
        source.next(selected[0])
    with pytest.raises(ProviderRefused):
        source.next(selected[1])
    assert calls == [1]
    assert source._counts == [1, 0]


@pytest.mark.parametrize(
    "query",
    [
        "api-version=2&%61udience=other",
        "api-version=2&AUDIENCE=other",
        "api-version=2&Aud%69ence=other",
        "api-version=2&audience=x&audience=y",
        "api-version=2&%2561udience=x",
        "api-version=2&%GG=x",
        "api-version=2&%ff=x",
        "api-version=2&=x",
        "api-version=2&&job=2",
        "api-version=2;audience=x",
        "api-version=2&job=2&JOB=3",
        "api-version=2&audience%00=x",
        "api-version=2&audience+=x",
    ],
)
def test_encoded_audience_duplicate_and_ambiguous_queries_refuse_before_binding(query):
    binding = tokens.JobBrokerBinding(
        "https://broker.example", "/job/2/token", query, "sha256:" + "1" * 64
    )
    with pytest.raises(ProviderRefused):
        binding.request_path(binding.origin + binding.path + "?" + query)


def test_actual_job_environment_url_credential_binds_without_request(
    installed_model, monkeypatch
):
    installed = InstalledRunnerCollection.from_installed()
    monkeypatch.setattr(
        tokens, "_spawn_request", lambda *_: pytest.fail("eager token request")
    )
    source = tokens.InstalledJobTokens.from_installed(installed)
    assert source._credential == "actual-job-test-credential"
    assert source._host == "broker.example"
    assert source._path == (
        "/job/2/token?api-version=2&job=2&audience="
        "urn%3Adotmac%3Agate0%3Arehearsal-issuer"
    )
    assert source._counts == [0, 0]
    assert source._cases[0] is installed.cases[0].projection
    assert source._cases[1] is installed.cases[1].projection
    assert "actual-job-test-credential" not in repr(source)


@pytest.mark.parametrize(
    "name,value",
    [
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://other.example/job/2/token?api-version=2&job=2",
        ),
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://broker.example/job/3/token?api-version=2&job=2",
        ),
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://broker.example/job/2/token?job=2&api-version=2",
        ),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "header\r\ninjection"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "x" * 32769),
        ("GITHUB_RUN_ID", "999"),
        ("RUNNER_NAME", "unqualified-runner"),
    ],
)
def test_actual_job_token_binding_rejects_runtime_changes(
    installed_model, monkeypatch, name, value
):
    installed = InstalledRunnerCollection.from_installed()
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        tokens, "_spawn_request", lambda *_: pytest.fail("request after refused bind")
    )
    with pytest.raises(ProviderRefused):
        tokens.InstalledJobTokens.from_installed(installed)


@pytest.mark.parametrize(
    "query",
    ["api-version=2&%61udience=x", "api-version=2&%GG=x", "api-version=2&AUDIENCE=x"],
)
def test_encoded_audience_refuses_before_actual_credential_read(
    installed_model, monkeypatch, query
):
    from dataclasses import replace

    installed = InstalledRunnerCollection.from_installed()
    installed = replace(installed, broker=replace(installed.broker, query=query))
    original = tokens.os.environ.get
    monkeypatch.setenv(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        installed.broker.origin + installed.broker.path + "?" + query,
    )

    def environment(name, default=None):
        assert (
            name != "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
        ), "credential read before URL refusal"
        return original(name, default)

    monkeypatch.setattr(tokens.os.environ, "get", environment)
    with pytest.raises(ProviderRefused):
        tokens.InstalledJobTokens.from_installed(installed)


@pytest.mark.parametrize(
    "claim",
    [
        "iss",
        "aud",
        "repository",
        "repository_id",
        "repository_owner_id",
        "environment",
        "ref",
        "workflow_ref",
        "workflow_sha",
        "event_name",
        "run_id",
        "run_attempt",
        "sub",
        "environment_node_id",
    ],
)
def test_every_actual_frozen_github_claim_restricts_token_output(
    installed_model, monkeypatch, claim
):
    installed = InstalledRunnerCollection.from_installed()
    source = tokens.InstalledJobTokens.from_installed(installed)
    case = installed.cases[0].projection
    assert claim in case.window.document["github"]
    monkeypatch.setattr(
        tokens, "_spawn_request", lambda *_: response(case, {claim: "swapped"})
    )
    with pytest.raises(ProviderRefused):
        source.next(case)
    assert source._counts == [1, 0]
    assert source._credential == ""


def test_full_frozen_github_token_passes_actual_bound_adapter(
    installed_model, monkeypatch
):
    installed = InstalledRunnerCollection.from_installed()
    source = tokens.InstalledJobTokens.from_installed(installed)
    case = installed.cases[0].projection
    assert len(case.window.document["github"]) == 14
    raw = response(case)
    monkeypatch.setattr(tokens, "_spawn_request", lambda *_: raw)
    assert source.next(case) == tokens.strict_object(raw, 65536)["value"]
