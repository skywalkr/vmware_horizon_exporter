ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
#LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/horizon_exporter /bin/horizon_exporter

EXPOSE      9181
USER        nobody
ENTRYPOINT  ["/bin/horizon_exporter"]