# PG_IMAGE is the digest-pinned official alpine image of one major, taken from images/images.toml
# ([[postgres]] image and digest): docker.io/library/postgres:<major>-alpine@sha256:<digest>.
ARG PG_IMAGE
# hadolint ignore=DL3006
FROM ${PG_IMAGE}

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-postgres" \
      org.opencontainers.image.description="Cite managed Postgres: the official image plus the cite-pg-job maintenance script" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

# One data layout for every major: PG 18 moved the image's VOLUME, so PGDATA is set explicitly. A fresh
# named volume copies this directory's owner and mode on first mount, so no init container is needed.
# /conf (the jobs' view) and /etc/cite-pg (the server's view) are the two names of the shared instance's
# config volume; the job user writes pg_hba.conf there and the server user reads it.
ENV PGDATA=/var/lib/postgresql/data/pgdata
RUN mkdir -p /var/lib/postgresql/data /conf /etc/cite-pg \
 && chown 70:70 /var/lib/postgresql/data \
 && chmod 0700 /var/lib/postgresql/data \
 && chown 10001:10001 /conf /etc/cite-pg \
 && chmod 0755 /conf /etc/cite-pg

COPY --chmod=0755 images/postgres/cite-pg-job /usr/local/bin/cite-pg-job

USER 70:70
