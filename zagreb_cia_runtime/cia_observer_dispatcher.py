"""Strict, serial STDIN dispatcher for parameterless Zagreb CIA observers."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Mapping
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
AUDIT_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
TIMESTAMP_PATTERN: Final = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
ALLOWED_CHECK_STATUS: Final = frozenset({"OK", "UNKNOWN", "ERROR"})
ALLOWED_BOOLEAN_STATUS: Final = frozenset({"TRUE", "FALSE", "UNKNOWN"})
ALLOWED_SHORT_REASONS: Final = frozenset(
    {
        "OTBR-Antwort besitzt ein unbekanntes Schema.",
        "Aktuelle OTBR-Rolle fehlt oder ist ungueltig.",
        "OTBR meldet einen explizit inaktiven Laufzeitzustand.",
        "OTBR-Rolle ist nicht eindeutig als routing-aktiv belegt.",
        "Aktive OTBR-Rolle belegt, Routingmerkmale jedoch unvollstaendig.",
        "Aktive OTBR-Rolle und aktuelle Routingmerkmale sind belegt.",
        "OTBR-REST-Abruf lieferte einen HTTP-Fehler.",
        "OTBR-REST-Abruf hat das Zeitlimit ueberschritten.",
        "OTBR-REST-Transport ist nicht erreichbar.",
        "OTBR-REST-Antwort ueberschreitet die erlaubte Groesse.",
        "OTBR-REST-Antwort ist kein gueltiges JSON.",
        "OTBR-Adapterfehler wurde sicher abgefangen.",
    }
)

Observer = Callable[[], dict[str, str]]
OBSERVER_REGISTRY: Final[Mapping[str, Observer]] = MappingProxyType(
    {
        "otbr_runtime_status": zagreb_ha_get_otbr_runtime_status,
    }
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
        return _envelope(
            request_id=request_id,
            observer=observer,
            status="ERROR",
            result=None,
        )

    if not _is_valid_result(result):
        return _envelope(
            request_id=request_id,
            observer=observer,
            status="ERROR",
            result=None,
        )

    return _envelope(
        request_id=request_id,
        observer=observer,
        status="COMPLETED",
        result=result,
    )


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
                response = dispatch_line(raw, registry)
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
    serve(sys.stdin.buffer, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
