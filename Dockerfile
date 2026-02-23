ARG TARGETOS
ARG TARGETARCH
FROM quay.io/prometheus/busybox-${TARGETOS}-${TARGETARCH}:latest

ARG TARGETOS
ARG TARGETARCH
COPY .build/${TARGETOS}-${TARGETARCH}/horizon_exporter /bin/horizon_exporter

EXPOSE      9181
USER        nobody
ENTRYPOINT  ["/bin/horizon_exporter"]