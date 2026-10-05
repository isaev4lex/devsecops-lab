# Runtime image only: the app is a single stdlib-only Python file, so there is
# nothing to compile and no build stage is needed.
#
# Base: distroless Python 3.13 on Debian 13. No shell, no package manager,
# default user nonroot (uid 65532). Pinned by digest so every build of a given
# commit starts from the same bytes; Dependabot proposes digest bumps.
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:774595d652a294b54c9bd575b2d9fdd1a4b47547dc17b8bfa4c0e953c64855b3

ARG REVISION=unknown

# No .pyc writes at runtime, so the container works with a read-only root filesystem.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_REVISION=${REVISION} \
    PORT=3000

WORKDIR /app
# Owned by root and read-only: the app user can run the code but not change it.
COPY --chown=0:0 --chmod=0444 main.py /app/main.py

USER 65532:65532
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/bin/python3", "/app/main.py", "healthcheck"]

ENTRYPOINT ["/usr/bin/python3", "/app/main.py"]
