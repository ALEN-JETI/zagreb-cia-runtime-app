FROM ghcr.io/home-assistant/base:3.22

ARG BUILD_VERSION=0.1.0
ARG BUILD_ARCH=aarch64

LABEL io.hass.version="$BUILD_VERSION" \
      io.hass.type="app" \
      io.hass.arch="$BUILD_ARCH" \
      org.opencontainers.image.title="Zagreb CIA Runtime" \
      org.opencontainers.image.description="Minimal isolated runtime proof for Zagreb HA CIA."

COPY run.sh /run.sh
RUN chmod 0755 /run.sh

CMD [ "/run.sh" ]

