# Zagreb CIA Runtime App

Public, credential-free Home Assistant App repository for the minimal Zagreb
CIA runtime skeleton.

The confirmed `0.2.0` release contains one parameterless internal read-only
check, `zagreb_ha_get_otbr_runtime_status`. It performs one bounded HTTP GET
against the fixed Supervisor-internal OTBR resource and returns only six
sanitized health fields.

The published `0.3.0` package adds a serial, allowlist-based
observer dispatcher on the official Home Assistant App STDIN channel. The only
registered observer is `otbr_runtime_status`; startup never invokes it. Every
request must contain exactly `observer` and a validated `request_id`. Invalid,
oversized or unknown requests fail closed and do not terminate the runtime.

Release `0.3.1` corrects the OTBR role semantics without changing the external
contract. OpenThread roles `child`, `router` and `leader` are treated as
attached. An attached role proves that the local OTBR endpoint is active, while
`routing_ready` becomes `TRUE` only when all required routing evidence is
present. Roles `disabled` and `detached` remain explicitly inactive; unknown
future role strings remain `UNKNOWN`.

The runtime still has no external ports, ingress, host networking, secrets,
Home Assistant API, Supervisor API, Docker API, dashboard, repair or external
AI access. STDIN is the only added runtime capability. The normal runtime start
does not depend on OTBR availability.

The accepted request contract is exactly:

```json
{"observer":"otbr_runtime_status","request_id":"audit-001"}
```

`request_id` is 1–64 characters and accepts only ASCII letters, digits, `.`,
`_`, `:` and `-`. Responses contain exactly `request_id`, `observer`, `status`
and `result`. `COMPLETED` means that the observer returned normally; its own
`check_status` remains `OK`, `UNKNOWN` or `ERROR`. Rejected requests and
contained dispatcher failures return `result: null` and never echo raw input.

The container image is published through the official Home Assistant builder
composite actions to:

`ghcr.io/alen-jeti/zagreb-cia-runtime`

## 0.3.4: direct runtime evidence

The single fixed GET uses /node, whose handler reads the current OpenThread
role in the main loop. The previous /api/node resource serializes a cached
device collection and is not a valid freshness guarantee. There is no fallback
to cached inventory or role-only data. checked_at is the observation time,
not a timestamp supplied by the device.

The six-field output and app privileges remain unchanged. An attached role
proves local Thread attachment only. The current /node response does not expose
omrIpv6Address, so routing_ready remains UNKNOWN; neither an end-to-end route
nor full system health is inferred. Disabled/detached is accepted only from
the direct response. Failed requests stay UNKNOWN/ERROR without a second URL.

## 0.3.5: local runtime process status

The additional parameterless `runtime_status` observer returns only a sanitized,
volatile process snapshot. It has no network, Home Assistant, credential,
file-I/O, persistence, thread, queue, automation or background capability.
Its result contains exactly `runtime_version`, `started_at`, `last_success_at`,
`last_success_age_seconds`, `freshness_status`, `last_error_status`,
`pending_requests`, `budget_status` and `checked_at`.

`started_at` is the dispatcher-state initialization time. `last_success_at` and
its monotonic age cover only a technically completed, schema-valid,
non-self-referential `otbr_runtime_status` run; a `runtime_status` request never
creates its own success evidence. This technical completion can coexist with an
OTBR result whose `check_status` is `ERROR`; the separate sanitized
`last_error_status` then reports `error` without detail. All such state is lost
on process restart and returns to `UNKNOWN`/`unknown` as applicable.

Version 0.3.5 intentionally always returns `freshness_status: "unknown"`:
the OTBR observer is not periodic and no canonical runtime-freshness threshold
exists. `pending_requests` and `budget_status` are both `UNKNOWN`, because the
serial dispatcher has no queue and the runtime has no budget source.

Primary source: https://github.com/openthread/ot-br-posix/blob/337711e7038d0b9c8fb46a1ce888ce7f9c4c0c35/src/rest/rest_web_server.cpp
