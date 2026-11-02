FROM oiran/srsran4g-ue-tools:0.29.4-rc1@sha256:218e848bd8cb59532d8cce9dcef8d6370944abd35b9b25aea9041671681e4d04

ARG POLARIS_SOURCE_SHA=unknown

RUN setcap -r /usr/bin/ping \
    && test -z "$(getcap /usr/bin/ping)"

LABEL org.opencontainers.image.title="POLARIS srsRAN4G UE tooling" \
      org.opencontainers.image.version="0.29.6-rc1" \
      org.opencontainers.image.revision="${POLARIS_SOURCE_SHA}" \
      org.opencontainers.image.description="Certified 0.29.4 UE tooling with ping file capability removed"
