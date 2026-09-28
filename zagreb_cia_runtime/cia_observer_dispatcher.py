"""Strict, serial STDIN dispatcher for parameterless Zagreb CIA observers."""

from __future__ import annotations

import json
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import BinaryIO, Final, TextIO

try:
    from .zagreb_otbr_runtime_adapter import (
        OUTPUT_FIELDS,
        zagreb_ha_get_otbr_runtime_status,
    )
except ImportError:
    from zagreb_otbr_runtime_adapter import (
        OUTPUT_FIELDS,
        zagreb_ha_get_otbr_runtime_status,
    )


MAX_REQUEST_BYTES: Final = 4096
REQUEST_FIELDS: Final = frozenset({"observer", "request_id"})
RUNTIME_VERSION: Final = "0.3.5"
RUNTIME_STATUS_OBSERVER: Final = "runtime_status"
OTBR_RUNTIME_STATUS_OBSERVER: Final = "otbr_runtime_status"
UNKNOWN: Final = "UNKNOWN"
AUDIT_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
TIMESTAMP_PATTERN: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
ALLOWED_CHECK_STATUS: Final = frozenset({"OK", "UNKNOWN", "ERROR"})
ALLOWED_BOOLEAN_STATUS: Final = frozenset({"TRUE", "FALSE", "UNKNOWN"})
RUNTIME_STATUS_FIELDS: Final = frozenset(
    {
        "runtime_version",
        "started_at",
        "last_success_at",
        "last_success_age_seconds",
        "freshness_status",
        "last_error_status",
        "pending_requests",
        "budget_status",
        "checked_at",
    }
)
ALLOWED_FRESHNESS_STATUS: Final = frozenset({"unknown"})
ALLOWED_LAST_ERROR_STATUS: Final = frozenset({"unknown", "none", "error"})
ALLOWED_SHORT_REASONS: Final = frozenset(
    {
        "OTBR-Antwort besitzt ein unbekanntes Schema.",
        "Aktuelle OTBR-Rolle fehlt oder ist ungueltig.",
        "OTBR meldet einen explizit inaktiven Laufzeitzustand.",
        "OTBR-Rolle ist nicht eindeutig als routing-aktiv belegt.",
        "Aktive OTBR-Rolle belegt, Routingmerkmale jedoch unvollstaendig.",
        "Aktive OTBR-Rolle und aktuelle Routingmerkmale sind belegt.",
        "OTBR meldet eine unbekannte Thread-Geraeterolle.",
        "OTBR ist angehaengt, Routingmerkmale jedoch unvollstaendig.",
        "OTBR ist angehaengt und aktuelle Routingmerkmale sind belegt.",
        "OTBR-REST-Abruf lieferte einen HTTP-Fehler.",
        "OTBR-REST-Abruf hat das Zeitlimit ueberschritten.",
        "OTBR-REST-Transport ist nicht erreichbar.",
        "OTBR-REST-Antwort ueberschreitet die erlaubte Groesse.",
        "OTBR-REST-Antwort ist kein gueltiges JSON.",
        "OTBR-Adapterfehler wurde sicher abgefangen.",
    }
)

Observer = Callable[[], dict[str, object]]


def _timestamp(now: datetime) -> str:
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class RuntimeStatusState:
    """Volatile dispatcher state; never persisted or derived from release files."""

    started_at: str
    started_monotonic: float | None
    last_success_at: str = UNKNOWN
    last_success_monotonic: float | None = None
    last_error_status: str = "unknown"

    def record_completed_otbr(
        self,
        result: Mapping[str, object],
        *,
        now: datetime,
        monotonic_now: float,
    ) -> None:
        """Record only a schema-valid, non-self-referential OTBR observer run."""

        self.last_success_at = _timestamp(now)
        self.last_success_monotonic = monotonic_now
        self.last_error_status = (
            "error" if result["check_status"] == "ERROR" else "none"
        )

    def record_otbr_error(self) -> None:
        self.last_error_status = "error"

    def snapshot(self, *, now: datetime, monotonic_now: float) -> dict[str, object]:
        age: int | str = UNKNOWN
        if (
            TIMESTAMP_PATTERN.fullmatch(self.last_success_at) is not None
            and self.last_success_monotonic is not None
        ):
            elapsed = monotonic_now - self.last_success_monotonic
            if elapsed >= 0:
                age = int(elapsed)
        return {
            "runtime_version": RUNTIME_VERSION,
            "started_at": self.started_at,
            "last_success_at": self.last_success_at,
            "last_success_age_seconds": age,
            "freshness_status": "unknown",
            "last_error_status": self.last_error_status,
            "pending_requests": UNKNOWN,
            "budget_status": UNKNOWN,
            "checked_at": _timestamp(now),
        }


def _new_runtime_status_state(
    *,
    now: datetime | None = None,
    monotonic_now: float | None = None,
) -> RuntimeStatusState:
    return RuntimeStatusState(
        started_at=_timestamp(now) if now is not None else UNKNOWN,
        started_monotonic=monotonic_now,
    )


def _runtime_status_observer(state: RuntimeStatusState) -> Observer:
    def observe() -> dict[str, object]:
        return state.snapshot(now=_utc_now(), monotonic_now=time.monotonic())

    return observe


def _observer_registry(state: RuntimeStatusState) -> Mapping[str, Observer]:
    return MappingProxyType(
        {
            OTBR_RUNTIME_STATUS_OBSERVER: zagreb_ha_get_otbr_runtime_status,
            RUNTIME_STATUS_OBSERVER: _runtime_status_observer(state),
        }
    )


_DEFAULT_RUNTIME_STATUS_STATE = _new_runtime_status_state()
OBSERVER_REGISTRY: Final[Mapping[str, Observer]] = _observer_registry(
    _DEFAULT_RUNTIME_STATUS_STATE
)


class _DuplicateJsonKey(ValueError):
    """Raised when a request attempts to redefine a JSON key."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _is_valid_request_id(value: object) -> bool:
    return isinstance(value, str) and AUDIT_ID_PATTERN.fullmatch(value) is not None


def _is_valid_result(result: object) -> bool:
    if not isinstance(result, dict) or frozenset(result) != OUTPUT_FIELDS:
        return False
    if not all(isinstance(value, str) for value in result.values()):
        return False
    return (
        result["check_status"] in ALLOWED_CHECK_STATUS
        and result["border_router_active"] in ALLOWED_BOOLEAN_STATUS
        and result["routing_ready"] in ALLOWED_BOOLEAN_STATUS
        and result["evidence_source"] == "otbr_rest_node"
        and TIMESTAMP_PATTERN.fullmatch(result["checked_at"]) is not None
        and result["short_reason"] in ALLOWED_SHORT_REASONS
    )


def _is_timestamp_or_unknown(value: object) -> bool:
    return value == UNKNOWN or (
        isinstance(value, str) and TIMESTAMP_PATTERN.fullmatch(value) is not None
    )


def _is_valid_runtime_status(result: object) -> bool:
    if not isinstance(result, dict) or frozenset(result) != RUNTIME_STATUS_FIELDS:
        return False
    age = result["last_success_age_seconds"]
    return (
        result["runtime_version"] == RUNTIME_VERSION
        and _is_timestamp_or_unknown(result["started_at"])
        and _is_timestamp_or_unknown(result["last_success_at"])
        and (
            age == UNKNOWN
            or (isinstance(age, int) and not isinstance(age, bool) and age >= 0)
        )
        and result["freshness_status"] in ALLOWED_FRESHNESS_STATUS
        and result["last_error_status"] in ALLOWED_LAST_ERROR_STATUS
        and result["pending_requests"] == UNKNOWN
        and result["budget_status"] == UNKNOWN
        and isinstance(result["checked_at"], str)
        and TIMESTAMP_PATTERN.fullmatch(result["checked_at"]) is not None
    )


def _is_valid_observer_result(observer: str, result: object) -> bool:
    if observer == OTBR_RUNTIME_STATUS_OBSERVER:
        return _is_valid_result(result)
    if observer == RUNTIME_STATUS_OBSERVER:
        return _is_valid_runtime_status(result)
    return False


def _envelope(
    *,
    request_id: str | None,
    observer: str | None,
    status: str,
    result: dict[str, str] | None,
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "observer": observer,
        "status": status,
        "result": result,
    }


def dispatch_line(
    raw: bytes,
    registry: Mapping[str, Observer] = OBSERVER_REGISTRY,
    runtime_state: RuntimeStatusState | None = None,
) -> dict[str, object]:
    """Validate and execute exactly one allowlisted, parameterless observer."""

    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey):
        return _envelope(
            request_id=None,
            observer=None,
            status="REJECTED",
            result=None,
        )

    if not isinstance(payload, dict):
        return _envelope(
            request_id=None,
            observer=None,
            status="REJECTED",
            result=None,
        )

    request_id_value = payload.get("request_id")
    observer_value = payload.get("observer")
    request_id = request_id_value if _is_valid_request_id(request_id_value) else None
    observer = (
        observer_value
        if isinstance(observer_value, str) and observer_value in registry
        else None
    )

    if frozenset(payload) != REQUEST_FIELDS or request_id is None or observer is None:
        return _envelope(
            request_id=request_id,
            observer=observer,
            status="REJECTED",
            result=None,
        )

    try:
        result = registry[observer]()
    except Exception:
        if observer == OTBR_RUNTIME_STATUS_OBSERVER and runtime_state is not None:
            runtime_state.record_otbr_error()
        return _envelope(
            request_id=request_id,
            observer=observer,
            status="ERROR",
            result=None,
        )

    if not _is_valid_observer_result(observer, result):
        if observer == OTBR_RUNTIME_STATUS_OBSERVER and runtime_state is not None:
            runtime_state.record_otbr_error()
        return _envelope(
            request_id=request_id,
            observer=observer,
            status="ERROR",
            result=None,
        )

    response = _envelope(
        request_id=request_id,
        observer=observer,
        status="COMPLETED",
        result=result,
    )
    if observer == OTBR_RUNTIME_STATUS_OBSERVER and runtime_state is not None:
        runtime_state.record_completed_otbr(
            result,
            now=_utc_now(),
            monotonic_now=time.monotonic(),
        )
    return response


def _read_bounded_line(input_stream: BinaryIO) -> tuple[bytes, bool] | None:
    raw = input_stream.readline(MAX_REQUEST_BYTES + 2)
    if raw == b"":
        return None

    has_newline = raw.endswith(b"\n")
    body = raw[:-1] if has_newline else raw
    if body.endswith(b"\r"):
        body = body[:-1]

    too_long = len(body) > MAX_REQUEST_BYTES
    if too_long and not has_newline:
        remainder = raw
        while remainder and not remainder.endswith(b"\n"):
            remainder = input_stream.readline(MAX_REQUEST_BYTES + 2)
    return body if not too_long else b"", too_long


def serve(
    input_stream: BinaryIO,
    output_stream: TextIO,
    registry: Mapping[str, Observer] = OBSERVER_REGISTRY,
    runtime_state: RuntimeStatusState | None = None,
) -> None:
    """Process requests serially until STDIN closes; request failures are contained."""

    while True:
        item = _read_bounded_line(input_stream)
        if item is None:
            return
        raw, too_long = item
        if too_long:
            response = _envelope(
                request_id=None,
                observer=None,
                status="REJECTED",
                result=None,
            )
        else:
            try:
                response = dispatch_line(raw, registry, runtime_state)
            except Exception:
                response = _envelope(
                    request_id=None,
                    observer=None,
                    status="ERROR",
                    result=None,
                )
        output_stream.write(json.dumps(response, separators=(",", ":")) + "\n")
        output_stream.flush()


def main() -> int:
    runtime_state = _new_runtime_status_state(
        now=_utc_now(), monotonic_now=time.monotonic()
    )
    serve(
        sys.stdin.buffer,
        sys.stdout,
        registry=_observer_registry(runtime_state),
        runtime_state=runtime_state,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
