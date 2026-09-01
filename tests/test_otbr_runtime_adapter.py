from __future__ import annotations

import json
import inspect
import socket
from datetime import UTC, datetime
from urllib import error

import pytest

from zagreb_cia_runtime import zagreb_otbr_runtime_adapter as adapter


NOW = datetime(2026, 9, 1, 8, 0, tzinfo=UTC)
EXPECTED_FIELDS = {
    "check_status",
    "border_router_active",
    "routing_ready",
    "evidence_source",
    "checked_at",
    "short_reason",
}
SENSITIVE_VALUES = (
    "ha-thread-secret",
    "fd11:22::1",
    "fd7a:9882::f000",
    "e11e23c164311ce642f93297b095b2f8",
    "a7b7d5d07d9ec2fa",
)


def active_payload() -> dict:
    return {
        "role": "leader",
        "omrIpv6Address": [SENSITIVE_VALUES[1]],
        "rlocAddress": SENSITIVE_VALUES[2],
        "leaderData": {"partitionId": 42},
        "baId": SENSITIVE_VALUES[3],
        "routerCount": 0,
        "networkName": SENSITIVE_VALUES[0],
        "extPanId": SENSITIVE_VALUES[4],
        "dataset": "must-not-leak",
    }


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None


class FakeFetcher:
    def __init__(self, response: FakeResponse | None = None, exc: Exception | None = None) -> None:
        self.response = response
        self.exc = exc
        self.request = None
        self.timeout = None

    def open(self, req, *, timeout: float):
        self.request = req
        self.timeout = timeout
        if self.exc:
            raise self.exc
        assert self.response is not None
        return self.response


def assert_allowlisted(result: dict[str, str]) -> None:
    serialized = json.dumps(result, sort_keys=True)
    assert set(result) == EXPECTED_FIELDS
    assert not any(value in serialized for value in (*SENSITIVE_VALUES, "must-not-leak"))


def test_active_runtime_is_healthy_and_sanitized() -> None:
    result = adapter._evaluate_node(active_payload(), now=NOW)
    assert result["check_status"] == "OK"
    assert result["border_router_active"] == "TRUE"
    assert result["routing_ready"] == "TRUE"
    assert_allowlisted(result)


@pytest.mark.parametrize("role", ["detached", "disabled"])
def test_explicit_inactive_runtime_is_false(role: str) -> None:
    payload = active_payload()
    payload["role"] = role
    result = adapter._evaluate_node(payload, now=NOW)
    assert result["check_status"] == "OK"
    assert result["border_router_active"] == "FALSE"
    assert result["routing_ready"] == "FALSE"
    assert_allowlisted(result)


@pytest.mark.parametrize(
    "exc",
    [socket.timeout(), error.URLError("private detail"), ConnectionError("private detail")],
)
def test_timeout_and_transport_fail_closed(exc: Exception) -> None:
    result = adapter._read_node(FakeFetcher(exc=exc), now=NOW)
    assert result["check_status"] == "ERROR"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert "private detail" not in json.dumps(result)
    assert_allowlisted(result)


def test_http_error_fails_closed() -> None:
    result = adapter._read_node(FakeFetcher(FakeResponse(b"{}", status=503)), now=NOW)
    assert result["check_status"] == "ERROR"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


def test_urllib_http_error_fails_closed() -> None:
    failure = error.HTTPError(adapter.OTBR_NODE_URL, 503, "private detail", None, None)
    result = adapter._read_node(FakeFetcher(exc=failure), now=NOW)
    assert result["check_status"] == "ERROR"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert "private detail" not in json.dumps(result)
    assert_allowlisted(result)


def test_invalid_json_is_unknown() -> None:
    result = adapter._read_node(FakeFetcher(FakeResponse(b"not-json")), now=NOW)
    assert result["check_status"] == "UNKNOWN"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


@pytest.mark.parametrize("payload", [[], {"unexpected": True}, {"role": 3}])
def test_unknown_or_missing_schema_is_unknown(payload) -> None:
    result = adapter._evaluate_node(payload, now=NOW)
    assert result["check_status"] == "UNKNOWN"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


@pytest.mark.parametrize(
    "field",
    ["omrIpv6Address", "rlocAddress", "leaderData", "baId", "routerCount"],
)
def test_missing_required_routing_field_is_unknown(field: str) -> None:
    payload = active_payload()
    del payload[field]
    result = adapter._evaluate_node(payload, now=NOW)
    assert result["check_status"] == "UNKNOWN"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


def test_unexpected_role_is_unknown_not_false() -> None:
    payload = active_payload()
    payload["role"] = "child"
    result = adapter._evaluate_node(payload, now=NOW)
    assert result["check_status"] == "UNKNOWN"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


def test_oversized_response_is_rejected() -> None:
    body = b"{" + b" " * adapter.MAX_RESPONSE_BYTES + b"}"
    result = adapter._read_node(FakeFetcher(FakeResponse(body)), now=NOW)
    assert result["check_status"] == "ERROR"
    assert result["border_router_active"] == "UNKNOWN"
    assert result["routing_ready"] == "UNKNOWN"
    assert_allowlisted(result)


def test_fetch_contract_is_fixed_get_only() -> None:
    fetcher = FakeFetcher(FakeResponse(json.dumps(active_payload()).encode()))
    adapter._read_node(fetcher, now=NOW)
    assert fetcher.request.full_url == adapter.OTBR_NODE_URL
    assert fetcher.request.get_method() == "GET"
    assert fetcher.request.headers == {"Accept": "application/json"}
    assert fetcher.timeout == adapter.REQUEST_TIMEOUT_SECONDS


def test_public_tool_contract_is_parameterless(monkeypatch: pytest.MonkeyPatch) -> None:
    fetcher = FakeFetcher(FakeResponse(json.dumps(active_payload()).encode()))
    monkeypatch.setattr(adapter.request, "build_opener", lambda *_handlers: fetcher)
    assert str(inspect.signature(adapter.zagreb_ha_get_otbr_runtime_status)) == "() -> 'dict[str, str]'"
    result = adapter.zagreb_ha_get_otbr_runtime_status()
    assert result["check_status"] == "OK"
    assert_allowlisted(result)


def test_unexpected_adapter_error_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_fetcher):
        raise RuntimeError("sensitive internal failure")

    monkeypatch.setattr(adapter, "_read_node", fail)
    result = adapter.zagreb_ha_get_otbr_runtime_status()
    assert result["check_status"] == "ERROR"
    assert "sensitive internal failure" not in json.dumps(result)
    assert_allowlisted(result)
