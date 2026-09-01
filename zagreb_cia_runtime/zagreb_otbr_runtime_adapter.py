"""Fail-closed, parameterless OTBR runtime check for Zagreb HA CIA."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any, Final, Protocol
from urllib import error, request


OTBR_NODE_URL: Final = "http://core-openthread-border-router:8081/api/node"
EVIDENCE_SOURCE: Final = "otbr_rest_node"
REQUEST_TIMEOUT_SECONDS: Final = 3.0
MAX_RESPONSE_BYTES: Final = 16 * 1024
ACTIVE_ROLES: Final = frozenset({"leader", "router"})
INACTIVE_ROLES: Final = frozenset({"disabled", "detached"})
OUTPUT_FIELDS: Final = frozenset(
    {
        "check_status",
        "border_router_active",
        "routing_ready",
        "evidence_source",
        "checked_at",
        "short_reason",
    }
)


class _Response(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> "_Response": ...

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None: ...


class _Fetcher(Protocol):
    def open(self, req: request.Request, *, timeout: float) -> _Response: ...


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class OtbrRuntimeResult:
    check_status: str
    border_router_active: str
    routing_ready: str
    evidence_source: str
    checked_at: str
    short_reason: str

    def as_dict(self) -> dict[str, str]:
        result = {
            "check_status": self.check_status,
            "border_router_active": self.border_router_active,
            "routing_ready": self.routing_ready,
            "evidence_source": self.evidence_source,
            "checked_at": self.checked_at,
            "short_reason": self.short_reason,
        }
        assert frozenset(result) == OUTPUT_FIELDS
        return result


def _timestamp(now: datetime | None) -> str:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _result(
    *,
    check_status: str,
    border_router_active: str = "UNKNOWN",
    routing_ready: str = "UNKNOWN",
    short_reason: str,
    now: datetime | None,
) -> dict[str, str]:
    return OtbrRuntimeResult(
        check_status=check_status,
        border_router_active=border_router_active,
        routing_ready=routing_ready,
        evidence_source=EVIDENCE_SOURCE,
        checked_at=_timestamp(now),
        short_reason=short_reason,
    ).as_dict()


def _has_nonempty_strings(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _evaluate_node(payload: Any, *, now: datetime | None = None) -> dict[str, str]:
    if not isinstance(payload, dict):
        return _result(
            check_status="UNKNOWN",
            short_reason="OTBR-Antwort besitzt ein unbekanntes Schema.",
            now=now,
        )

    role = payload.get("role")
    if not isinstance(role, str):
        return _result(
            check_status="UNKNOWN",
            short_reason="Aktuelle OTBR-Rolle fehlt oder ist ungueltig.",
            now=now,
        )
    role = role.strip().lower()

    if role in INACTIVE_ROLES:
        return _result(
            check_status="OK",
            border_router_active="FALSE",
            routing_ready="FALSE",
            short_reason="OTBR meldet einen explizit inaktiven Laufzeitzustand.",
            now=now,
        )

    if role not in ACTIVE_ROLES:
        return _result(
            check_status="UNKNOWN",
            short_reason="OTBR-Rolle ist nicht eindeutig als routing-aktiv belegt.",
            now=now,
        )

    routing_evidence_complete = (
        _has_nonempty_strings(payload.get("omrIpv6Address"))
        and isinstance(payload.get("rlocAddress"), str)
        and bool(payload["rlocAddress"].strip())
        and isinstance(payload.get("leaderData"), dict)
        and bool(payload["leaderData"])
        and isinstance(payload.get("baId"), str)
        and bool(payload["baId"].strip())
        and isinstance(payload.get("routerCount"), int)
        and not isinstance(payload.get("routerCount"), bool)
        and payload["routerCount"] >= 0
    )
    if not routing_evidence_complete:
        return _result(
            check_status="UNKNOWN",
            short_reason="Aktive OTBR-Rolle belegt, Routingmerkmale jedoch unvollstaendig.",
            now=now,
        )

    return _result(
        check_status="OK",
        border_router_active="TRUE",
        routing_ready="TRUE",
        short_reason="Aktive OTBR-Rolle und aktuelle Routingmerkmale sind belegt.",
        now=now,
    )


def _read_node(fetcher: _Fetcher, *, now: datetime | None = None) -> dict[str, str]:
    req = request.Request(
        OTBR_NODE_URL,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with fetcher.open(req, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.status != HTTPStatus.OK:
                return _result(
                    check_status="ERROR",
                    short_reason="OTBR-REST-Abruf lieferte einen HTTP-Fehler.",
                    now=now,
                )
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (TimeoutError, socket.timeout):
        return _result(
            check_status="ERROR",
            short_reason="OTBR-REST-Abruf hat das Zeitlimit ueberschritten.",
            now=now,
        )
    except error.HTTPError:
        return _result(
            check_status="ERROR",
            short_reason="OTBR-REST-Abruf lieferte einen HTTP-Fehler.",
            now=now,
        )
    except (error.URLError, OSError):
        return _result(
            check_status="ERROR",
            short_reason="OTBR-REST-Transport ist nicht erreichbar.",
            now=now,
        )

    if len(raw) > MAX_RESPONSE_BYTES:
        return _result(
            check_status="ERROR",
            short_reason="OTBR-REST-Antwort ueberschreitet die erlaubte Groesse.",
            now=now,
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _result(
            check_status="UNKNOWN",
            short_reason="OTBR-REST-Antwort ist kein gueltiges JSON.",
            now=now,
        )
    return _evaluate_node(payload, now=now)


def zagreb_ha_get_otbr_runtime_status() -> dict[str, str]:
    """Return only the six allowlisted fields; never propagate adapter errors."""

    try:
        opener = request.build_opener(_NoRedirectHandler())
        return _read_node(opener)
    except Exception:
        return _result(
            check_status="ERROR",
            short_reason="OTBR-Adapterfehler wurde sicher abgefangen.",
            now=None,
        )


if __name__ == "__main__":
    print(json.dumps(zagreb_ha_get_otbr_runtime_status(), separators=(",", ":")))
