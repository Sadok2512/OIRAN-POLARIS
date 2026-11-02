FROM oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43

ARG POLARIS_SOURCE_SHA=unknown

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       iperf3=3.16-1build2 \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="POLARIS srsRAN4G UE tooling" \
      org.opencontainers.image.version="0.29.4" \
      org.opencontainers.image.revision="${POLARIS_SOURCE_SHA}" \
      org.opencontainers.image.description="Certified srsRAN4G image plus pinned iperf3 only"
