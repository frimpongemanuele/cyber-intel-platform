# syntax=docker/dockerfile:1.7
# Egress proxy: Debian's squid, configured only by the generated squid.conf.
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:DEBIAN_DIGEST
FROM ${DEBIAN_IMAGE}
# Debian package versions are not pinned: security fixes arrive by rebuilding (weekly CI
# rebuild + Trivy scan); the image digest above pins everything else.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends squid \
 && rm -rf /var/lib/apt/lists/* /etc/squid/conf.d
COPY squid.conf /etc/squid/squid.conf
USER proxy
EXPOSE 3128 3129
ENTRYPOINT ["/usr/sbin/squid", "-N", "-f", "/etc/squid/squid.conf"]
