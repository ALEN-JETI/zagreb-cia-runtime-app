FROM ghcr.io/home-assistant/base:3.22

ARG BUILD_VERSION=0.3.0
ARG BUILD_ARCH=aarch64

LABEL io.hass.version="$BUILD_VERSION" \
      io.hass.type="app" \
      io.hass.arch="$BUILD_ARCH" \
      org.opencontainers.image.title="Zagreb CIA Runtime" \
      org.opencontainers.image.description="Isolated Zagreb HA CIA runtime with an OTBR read-only check."

RUN apk add --no-cache python3

COPY run.sh /run.sh
COPY zagreb_otbr_runtime_adapter.py /zagreb_otbr_runtime_adapter.py
COPY cia_observer_dispatcher.py /cia_observer_dispatcher.py
RUN chmod 0755 /run.sh \
    && chmod 0444 /zagreb_otbr_runtime_adapter.py \
    && chmod 0444 /cia_observer_dispatcher.py

CMD [ "/run.sh" ]
