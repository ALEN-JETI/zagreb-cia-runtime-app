from __future__ import annotations

import io
import json
import unittest
from pathlib import Path

from zagreb_cia_runtime import cia_observer_dispatcher as dispatcher


def adapter_result(check_status: str = "OK", *, marker: int = 0) -> dict[str, str]:
    boolean_status = "TRUE" if check_status == "OK" else "UNKNOWN"
    return {
        "check_status": check_status,
        "border_router_active": boolean_status,
        "routing_ready": boolean_status,
        "evidence_source": "otbr_rest_node",
        "checked_at": f"2026-09-02T00:00:0{marker}Z",
        "short_reason": (
            "Aktive OTBR-Rolle und aktuelle Routingmerkmale sind belegt."
            if check_status == "OK"
            else "OTBR-REST-Transport ist nicht erreichbar."
            if check_status == "ERROR"
            else "OTBR-Rolle ist nicht eindeutig als routing-aktiv belegt."
        ),
    }


def request(request_id: str = "audit-001") -> bytes:
    return json.dumps(
        {"observer": "otbr_runtime_status", "request_id": request_id},
        separators=(",", ":"),
    ).encode()


def run_stream(lines: list[bytes], observer) -> list[dict[str, object]]:
    input_stream = io.BytesIO(b"".join(line + b"\n" for line in lines))
    output_stream = io.StringIO()
    dispatcher.serve(
        input_stream,
        output_stream,
        {"otbr_runtime_status": observer},
    )
    return [json.loads(line) for line in output_stream.getvalue().splitlines()]


class ObserverDispatcherTests(unittest.TestCase):
    def fail_observer(self) -> dict[str, str]:
        self.fail("Observer must not be called")

    def test_valid_request_runs_only_registered_parameterless_observer(self) -> None:
        calls = 0

        def observer() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return adapter_result()

        response = run_stream([request()], observer)[0]
        self.assertEqual(calls, 1)
        self.assertEqual(
            response,
            {
                "request_id": "audit-001",
                "observer": "otbr_runtime_status",
                "status": "COMPLETED",
                "result": adapter_result(),
            },
        )

    def test_unknown_observer_is_rejected_without_call(self) -> None:
        raw = json.dumps({"observer": "unknown", "request_id": "audit-002"}).encode()
        response = dispatcher.dispatch_line(
            raw, {"otbr_runtime_status": self.fail_observer}
        )
        self.assertEqual(
            response,
            {
                "request_id": "audit-002",
                "observer": None,
                "status": "REJECTED",
                "result": None,
            },
        )

    def test_missing_or_invalid_request_id_is_rejected(self) -> None:
        payloads = [
            {"observer": "otbr_runtime_status"},
            {"observer": "otbr_runtime_status", "request_id": None},
            {"observer": "otbr_runtime_status", "request_id": ""},
            {"observer": "otbr_runtime_status", "request_id": "bad id"},
            {"observer": "otbr_runtime_status", "request_id": "a" * 65},
            {"observer": "otbr_runtime_status", "request_id": 7},
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                response = dispatcher.dispatch_line(
                    json.dumps(payload).encode(),
                    {"otbr_runtime_status": self.fail_observer},
                )
                self.assertEqual(response["status"], "REJECTED")
                self.assertIsNone(response["request_id"])
                self.assertIsNone(response["result"])

    def test_additional_fields_are_rejected_without_call(self) -> None:
        raw = json.dumps(
            {
                "observer": "otbr_runtime_status",
                "request_id": "audit-003",
                "url": "http://forbidden.invalid",
            }
        ).encode()
        response = dispatcher.dispatch_line(
            raw, {"otbr_runtime_status": self.fail_observer}
        )
        self.assertEqual(response["status"], "REJECTED")
        self.assertIsNone(response["result"])

    def test_invalid_json_or_wrong_root_type_is_rejected(self) -> None:
        for raw in (b"{", b"not-json", b"[]", b"\xff"):
            with self.subTest(raw=raw):
                response = dispatcher.dispatch_line(
                    raw, {"otbr_runtime_status": self.fail_observer}
                )
                self.assertEqual(
                    response,
                    {
                        "request_id": None,
                        "observer": None,
                        "status": "REJECTED",
                        "result": None,
                    },
                )

    def test_duplicate_json_fields_are_rejected(self) -> None:
        raw = (
            b'{"observer":"otbr_runtime_status","observer":"otbr_runtime_status",'
            b'"request_id":"audit-004"}'
        )
        self.assertEqual(dispatcher.dispatch_line(raw)["status"], "REJECTED")

    def test_overlong_input_is_drained_and_next_request_still_runs(self) -> None:
        calls = 0

        def observer() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return adapter_result()

        responses = run_stream(
            [b"x" * (dispatcher.MAX_REQUEST_BYTES + 100), request("audit-005")],
            observer,
        )
        self.assertEqual(
            [item["status"] for item in responses], ["REJECTED", "COMPLETED"]
        )
        self.assertEqual(calls, 1)

    def test_adapter_ok_unknown_and_error_are_completed_results(self) -> None:
        for check_status in ("OK", "UNKNOWN", "ERROR"):
            with self.subTest(check_status=check_status):
                response = run_stream(
                    [request()], lambda status=check_status: adapter_result(status)
                )[0]
                self.assertEqual(response["status"], "COMPLETED")
                self.assertEqual(response["result"]["check_status"], check_status)

    def test_unexpected_observer_exception_is_contained_and_redacted(self) -> None:
        def observer() -> dict[str, str]:
            raise RuntimeError("secret runtime detail")

        response = run_stream([request()], observer)[0]
        serialized = json.dumps(response)
        self.assertEqual(response["status"], "ERROR")
        self.assertIsNone(response["result"])
        self.assertNotIn("secret runtime detail", serialized)

    def test_malformed_or_sensitive_adapter_result_is_not_forwarded(self) -> None:
        sensitive = adapter_result()
        sensitive["short_reason"] = "fd00::secret rloc dataset leader"
        response = run_stream([request()], lambda: sensitive)[0]
        serialized = json.dumps(response)
        self.assertEqual(response["status"], "ERROR")
        self.assertIsNone(response["result"])
        for forbidden in ("fd00", "rloc", "dataset", "leader"):
            self.assertNotIn(forbidden, serialized)

    def test_dispatcher_continues_after_rejection_and_exception(self) -> None:
        calls = 0

        def observer() -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("contained")
            return adapter_result(marker=2)

        responses = run_stream(
            [b"invalid", request("audit-006"), request("audit-007")], observer
        )
        self.assertEqual(
            [item["status"] for item in responses],
            ["REJECTED", "ERROR", "COMPLETED"],
        )
        self.assertEqual(responses[2]["request_id"], "audit-007")

    def test_follow_up_requests_execute_serially_in_input_order(self) -> None:
        call_order: list[int] = []

        def observer() -> dict[str, str]:
            call_order.append(len(call_order) + 1)
            return adapter_result(marker=call_order[-1])

        responses = run_stream(
            [request("audit-008"), request("audit-009")], observer
        )
        self.assertEqual(call_order, [1, 2])
        self.assertEqual(
            [item["request_id"] for item in responses], ["audit-008", "audit-009"]
        )
        self.assertEqual(
            [item["result"]["checked_at"] for item in responses],
            ["2026-09-02T00:00:01Z", "2026-09-02T00:00:02Z"],
        )

    def test_empty_startup_input_never_invokes_observer(self) -> None:
        calls = 0

        def observer() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return adapter_result()

        output_stream = io.StringIO()
        dispatcher.serve(
            io.BytesIO(b""),
            output_stream,
            {"otbr_runtime_status": observer},
        )
        self.assertEqual(calls, 0)
        self.assertEqual(output_stream.getvalue(), "")

    def test_dispatcher_source_has_no_arbitrary_execution_facilities(self) -> None:
        source = Path(dispatcher.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "importlib", "eval(", "exec("):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
