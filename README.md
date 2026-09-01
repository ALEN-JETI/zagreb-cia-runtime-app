# Zagreb CIA Runtime App

Public, credential-free Home Assistant App repository for the minimal Zagreb
CIA runtime skeleton.

The confirmed `0.1.0` release proves that the protected runtime container can
be installed and started inside Home Assistant OS.

The prepared, unpublished `0.2.0` package adds one parameterless internal
read-only check, `zagreb_ha_get_otbr_runtime_status`. It performs one bounded
HTTP GET against the fixed Supervisor-internal OTBR resource
`http://core-openthread-border-router:8081/api/node`. It returns only six
sanitized health fields and fails closed without terminating the runtime.

The runtime still has no external ports, ingress, host networking, secrets,
Home Assistant API, Supervisor API, dashboard, repair or external AI access.
The normal runtime start does not depend on OTBR availability.

The container image is published through the official Home Assistant builder
composite actions to:

`ghcr.io/alen-jeti/zagreb-cia-runtime`
