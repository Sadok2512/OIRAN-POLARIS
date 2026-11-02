FROM alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

ARG POLARIS_SOURCE_SHA=f9e9eb78e03a406dba5cd12dbf386e5fdeef2e8a

RUN apk add --no-cache \
      iperf3=3.17.1-r0 \
      iproute2=6.9.0-r0 \
      iputils=20240117-r0 \
    && addgroup -S -g 65532 polaris \
    && adduser -S -D -H -u 65532 -G polaris polaris

LABEL org.opencontainers.image.title="POLARIS LTE SGi DN sidecar" \
      org.opencontainers.image.version="0.29.3" \
      org.opencontainers.image.revision="${POLARIS_SOURCE_SHA}" \
      org.opencontainers.image.description="Minimal SGi-only iperf3 and ICMP endpoint"

USER 65532:65532
EXPOSE 5201/tcp 5201/udp
ENTRYPOINT ["/usr/bin/iperf3"]
CMD ["-s"]
