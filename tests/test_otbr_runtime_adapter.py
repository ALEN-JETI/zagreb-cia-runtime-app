from __future__ import annotations

import inspect
import json
import socket
import unittest
from datetime import UTC, datetime
from unittest.mock import patch
from urllib import error

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
        if self.response is None:
            raise AssertionError("response required")
        return self.response


class OtbrRuntimeAdapterTests(unittest.TestCase):
    def assert_allowlisted(self, result: dict[str, str]) -> None:
        serialized = json.dumps(result, sort_keys=True)
        self.assertEqual(set(result), EXPECTED_FIELDS)
        self.assertFalse(
            any(value in serialized for value in (*SENSITIVE_VALUES, "must-not-leak"))
        )

    def test_active_runtime_is_healthy_and_sanitized(self) -> None:
        result = adapter._evaluate_node(active_payload(), now=NOW)
        self.assertEqual(result["check_status"], "OK")
        self.assertEqual(result["border_router_active"], "TRUE")
        self.assertEqual(result["routing_ready"], "TRUE")
        self.assert_allowlisted(result)

    def test_explicit_inactive_runtime_is_false(self) -> None:
        for role in ("detached", "disabled"):
            with self.subTest(role=role):
                payload = active_payload()
                payload["role"] = role
                result = adapter._evaluate_node(payload, now=NOW)
                self.assertEqual(result["check_status"], "OK")
                self.assertEqual(result["border_router_active"], "FALSE")
                self.assertEqual(result["routing_ready"], "FALSE")
                self.assert_allowlisted(result)

    def test_timeout_and_transport_fail_closed(self) -> None:
        failures = [
            socket.timeout(),
            error.URLError("private detail"),
            ConnectionError("private detail"),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                result = adapter._read_node(FakeFetcher(exc=failure), now=NOW)
                self.assertEqual(result["check_status"], "ERROR")
                self.assertEqual(result["border_router_active"], "UNKNOWN")
                self.assertEqual(result["routing_ready"], "UNKNOWN")
                self.assertNotIn("private detail", json.dumps(result))
                self.assert_allowlisted(result)

    def test_http_error_fails_closed(self) -> None:
        result = adapter._read_node(FakeFetcher(FakeResponse(b"{}", status=503)), now=NOW)
        self.assertEqual(result["check_status"], "ERROR")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assert_allowlisted(result)

    def test_urllib_http_error_fails_closed(self) -> None:
        failure = error.HTTPError(adapter.OTBR_NODE_URL, 503, "private detail", None, None)
        result = adapter._read_node(FakeFetcher(exc=failure), now=NOW)
        self.assertEqual(result["check_status"], "ERROR")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assertNotIn("private detail", json.dumps(result))
        self.assert_allowlisted(result)

    def test_invalid_json_is_unknown(self) -> None:
        result = adapter._read_node(FakeFetcher(FakeResponse(b"not-json")), now=NOW)
        self.assertEqual(result["check_status"], "UNKNOWN")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assert_allowlisted(result)

    def test_unknown_or_missing_schema_is_unknown(self) -> None:
        for payload in ([], {"unexpected": True}, {"role": 3}):
            with self.subTest(payload=payload):
                result = adapter._evaluate_node(payload, now=NOW)
                self.assertEqual(result["check_status"], "UNKNOWN")
                self.assertEqual(result["border_router_active"], "UNKNOWN")
                self.assertEqual(result["routing_ready"], "UNKNOWN")
                self.assert_allowlisted(result)

    def test_missing_required_routing_field_is_unknown(self) -> None:
        for field in ("omrIpv6Address", "rlocAddress", "leaderData", "baId", "routerCount"):
            with self.subTest(field=field):
                payload = active_payload()
                del payload[field]
                result = adapter._evaluate_node(payload, now=NOW)
                self.assertEqual(result["check_status"], "UNKNOWN")
                self.assertEqual(result["border_router_active"], "UNKNOWN")
                self.assertEqual(result["routing_ready"], "UNKNOWN")
                self.assert_allowlisted(result)

    def test_unexpected_role_is_unknown_not_false(self) -> None:
        payload = active_payload()
        payload["role"] = "child"
        result = adapter._evaluate_node(payload, now=NOW)
        self.assertEqual(result["check_status"], "UNKNOWN")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assert_allowlisted(result)

    def test_oversized_response_is_rejected(self) -> None:
        body = b"{" + b" " * adapter.MAX_RESPONSE_BYTES + b"}"
        result = adapter._read_node(FakeFetcher(FakeResponse(body)), now=NOW)
        self.assertEqual(result["check_status"], "ERROR")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assert_allowlisted(result)

    def test_fetch_contract_is_fixed_get_only(self) -> None:
        fetcher = FakeFetcher(FakeResponse(json.dumps(active_payload()).encode()))
        adapter._read_node(fetcher, now=NOW)
        self.assertEqual(fetcher.request.full_url, adapter.OTBR_NODE_URL)
        self.assertEqual(fetcher.request.get_method(), "GET")
        self.assertEqual(fetcher.request.headers, {"Accept": "application/json"})
        self.assertEqual(fetcher.timeout, adapter.REQUEST_TIMEOUT_SECONDS)

    def test_public_tool_contract_is_parameterless(self) -> None:
        fetcher = FakeFetcher(FakeResponse(json.dumps(active_payload()).encode()))
        with patch.object(adapter.request, "build_opener", return_value=fetcher):
            self.assertEqual(
                str(inspect.signature(adapter.zagreb_ha_get_otbr_runtime_status)),
                "() -> 'dict[str, str]'",
            )
            result = adapter.zagreb_ha_get_otbr_runtime_status()
        self.assertEqual(result["check_status"], "OK")
        self.assert_allowlisted(result)

    def test_unexpected_adapter_error_is_contained(self) -> None:
        with patch.object(
            adapter,
            "_read_node",
            side_effect=RuntimeError("sensitive internal failure"),
        ):
            result = adapter.zagreb_ha_get_otbr_runtime_status()
        self.assertEqual(result["check_status"], "ERROR")
        self.assertNotIn("sensitive internal failure", json.dumps(result))
        self.assert_allowlisted(result)


if __name__ == "__main__":
    unittest.main()
