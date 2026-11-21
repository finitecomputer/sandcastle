# The home study's root (docs/nitro-spike.md, "A home"): celld's own release
# image's base and package, with the celld built on the parent from the
# fork's selfhost line, and curl and procps for the study's execs.
ARG BASE
FROM ${BASE}
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl procps && \
    rm -rf /var/lib/apt/lists/*
COPY celld /usr/local/bin/celld
