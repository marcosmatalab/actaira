# Actaira in a container, for a pipeline that has docker and not python.
# Nothing here is published anywhere. This file builds an image locally:
# `docker build -t actaira . && docker run --rm actaira --version` is the
# whole of it.
#
# The image carries the tool and nothing else: no tests, no docs, and above all
# no `evals/artifacts`, which is a directory of crafted malicious pickles that
# has no business inside any image. What goes in is decided by the COPY lines
# below and enforced by .dockerignore.
#
# On reproducibility: the base is pinned to a tag, not a digest. Pinning the
# digest is stricter and is the right thing to do in a release pipeline, where
# the digest is resolved on the machine that builds and recorded there:
#
#   FROM python:3.12-slim@sha256:<digest resolved by your own docker pull>
#
# A digest copied into a repository from somewhere else is a claim the
# repository cannot check, which is the kind of claim this project does not
# make. The version of the tool inside the image is not stamped in a label for
# the same reason: `docker run actaira --version` reads it from the package.
FROM python:3.12-slim

# No `org.opencontainers.image.source`. That label is a URL a consumer is
# expected to be able to fetch the source from, and there is none: this is a
# local tree. A label pointing at a repository that does not exist is worse
# than a missing label, because tooling reads it and nothing checks it.
LABEL org.opencontainers.image.title="actaira" \
      org.opencontainers.image.description="Local-first AI assurance for model artifacts and agents: static inspection, evidence lifecycle, policy-as-code, agent governance and verifiable attestations. Nothing is ever loaded or executed." \
      org.opencontainers.image.licenses="MIT"

# No .pyc files and no pip cache, so the layer holds the package and not a copy
# of everything used to install it.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Exactly what the package needs to build: the metadata, the readme the
# metadata points at, the licence, and the source.
COPY pyproject.toml README.md LICENSE /src/
COPY src /src/src

RUN python -m pip install --no-cache-dir /src \
    && rm -rf /src /root/.cache

# A fixed uid, so a workspace bind-mounted from a CI runner has predictable
# ownership, and a non-root one, because a tool that reads untrusted artifacts
# should not be able to write to the image it runs from.
RUN groupadd --gid 10001 actaira \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin actaira
USER 10001:10001

# Where a caller is expected to mount the models. Nothing is written here by
# the tool unless `--out` asks for it.
WORKDIR /work

ENTRYPOINT ["actaira"]
CMD ["--help"]
