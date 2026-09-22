import json
import unittest
from urllib import error
from zagreb_cia_runtime import zagreb_otbr_runtime_adapter as adapter
from zagreb_cia_runtime.cia_observer_dispatcher import _is_valid_result
from test_otbr_runtime_adapter import FakeFetcher, FakeResponse, NOW, active_payload


class CountingFetcher(FakeFetcher):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = []

    def open(self, req, *, timeout):
        self.calls.append((req.full_url, req.get_method(), timeout))
        return super().open(req, timeout=timeout)


class DirectRuntimeTests(unittest.TestCase):
    def test_direct_upstream_shape_proves_attachment_not_full_routing(self):
        # Fields emitted by Node2Json for GetNodeInfo; no OMR field.
        payload = {
            "state": "leader", "baId": "0123456789abcdef0123456789abcdef",
            "baState": "", "routerCount": 9, "rlocAddress": "fd00::fc00",
            "extAddress": "0123456789abcdef", "networkName": "test-network",
            "rloc16": "0x0000", "routerId": 0,
            "leaderData": {"partitionId": 42, "weighting": 64,
                           "dataVersion": 1, "stableDataVersion": 1,
                           "leaderRouterId": 0},
            "extPanId": "0123456789abcdef",
        }
        f = CountingFetcher(FakeResponse(json.dumps(payload).encode()))
        result = adapter._read_node(f, now=NOW)
        self.assertEqual(result["border_router_active"], "TRUE")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assertEqual(result["check_status"], "UNKNOWN")
        self.assertEqual(f.calls, [
            ("http://core-openthread-border-router:8081/node", "GET", 3.0)])
        self.assertTrue(_is_valid_result(result))
        self.assertNotIn("test-network", json.dumps(result))

    def test_transport_failure_never_falls_back_to_cached_inventory(self):
        f = CountingFetcher(exc=error.URLError("sensitive"))
        result = adapter._read_node(f, now=NOW)
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.calls[0][0], "http://core-openthread-border-router:8081/node")
        self.assertEqual(result["border_router_active"], "UNKNOWN")
        self.assertEqual(result["routing_ready"], "UNKNOWN")
        self.assertTrue(_is_valid_result(result))

    def test_role_only_inventory_cannot_claim_active_or_inactive(self):
        for role in ("leader", "disabled", "detached"):
            payload = active_payload()
            del payload["state"]
            payload["role"] = role
            result = adapter._evaluate_node(payload, now=NOW)
            self.assertEqual(result["border_router_active"], "UNKNOWN")
            self.assertEqual(result["routing_ready"], "UNKNOWN")

    def test_inactive_direct_response_needs_no_routing_metadata(self):
        for state in ("disabled", "detached"):
            f = CountingFetcher(FakeResponse(json.dumps({"state": state}).encode()))
            result = adapter._read_node(f, now=NOW)
            self.assertEqual(result["border_router_active"], "FALSE")
            self.assertEqual(result["routing_ready"], "FALSE")
            self.assertEqual(len(f.calls), 1)
            self.assertTrue(_is_valid_result(result))

    def test_http_failure_never_falls_back(self):
        f = CountingFetcher(FakeResponse(b"cached-data-not-allowed", status=503))
        result = adapter._read_node(f, now=NOW)
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(result["check_status"], "ERROR")
        self.assertEqual(result["border_router_active"], "UNKNOWN")

    def test_payload_timestamp_is_not_reported_as_observation_time(self):
        data = active_payload()
        data["checked_at"] = "2000-01-01T00:00:00Z"
        f = CountingFetcher(FakeResponse(json.dumps(data).encode()))
        result = adapter._read_node(f, now=NOW)
        self.assertEqual(result["checked_at"], NOW.isoformat().replace("+00:00", "Z"))
        self.assertEqual(len(result), 6)
