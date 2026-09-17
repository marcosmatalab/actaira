# Actaira in a container, for a pipeline that has docker and not python.
# Nothing here is published anywhere. This file builds an image locally:
# `docker build -t actaira . && docker run --rm actaira --version` is the
# whole of it.
#
# The image carries the tool and nothing else: no tests and no docs. What goes
# in is decided by the COPY lines below and enforced by .dockerignore. It used
# to say "and above all no `evals/artifacts`, a directory of crafted malicious
# pickles"; that directory went to archive/model-scanner with the scanner, and a
# comment guarding against a hazard the tree no longer has reads as a description
# of a tree that still has it.
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
      org.opencontainers.image.description="An independent witness for AI agents: capture what an agent did from outside the process, at a declared capture level, into a trace a third party can read offline. Nothing is scored." \
      org.opencontainers.image.licenses="Apache-2.0"

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

# Where a caller is expected to mount the workspace. Nothing is written here by
# the tool unless `--out` asks for it. It said "the models" until phase A, which
# was the scanner's noun for the thing being looked at; what gets mounted now is
# whatever the agent runs against.
WORKDIR /work

ENTRYPOINT ["actaira"]
CMD ["--help"]
