# Zagreb CIA Runtime App

Public, credential-free Home Assistant App repository for the minimal Zagreb
CIA runtime skeleton.

The confirmed `0.2.0` release contains one parameterless internal read-only
check, `zagreb_ha_get_otbr_runtime_status`. It performs one bounded HTTP GET
against the fixed Supervisor-internal OTBR resource and returns only six
sanitized health fields.

The prepared, unpublished `0.3.0` package adds a serial, allowlist-based
observer dispatcher on the official Home Assistant App STDIN channel. The only
registered observer is `otbr_runtime_status`; startup never invokes it. Every
request must contain exactly `observer` and a validated `request_id`. Invalid,
oversized or unknown requests fail closed and do not terminate the runtime.

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
