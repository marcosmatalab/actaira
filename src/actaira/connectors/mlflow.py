"""An MLflow tracking server: the registry that knows the most and publishes no digest.

Design note D-90, and the thing that makes this connector different from the
other five.

MLflow is where a model artifact usually has the most context around it: a run,
a set of parameters, metrics, a stage, a version number that a deployment
pipeline reads. It is also, of the sources in this package, the only one that
publishes no digest of any kind. `artifacts/list` returns a path, a directory
flag and a file size, and that is all. So every artifact from here carries
`declared_sha256 = None`, `stage()` reports `digest_confirmed: false` for all
of them, and the notes say it in words, because a report where a run's model
file sits beside a HuggingFace file with a confirmed digest and looks the same
would be telling the reader something false by omission.

The size is the only claim the server makes, and a size is not a digest. It is
kept because a fetch that returns a different number of bytes than the registry
promised is worth seeing, and `stage()` records the measured size beside it.

Design note D-90b, on what "the model registry" means here and what it does not.

Two listings live behind one connector, chosen by what the URI names:

  * `mlflow://host` lists registered models, which are names and stages rather
    than files. Each becomes an artifact whose `uri` is its `source` location,
    and that location is very often not something this tool can fetch: MLflow
    stores it as `s3://...`, `dbfs:/...`, `gs://...` or a local path on the
    tracking server. Those are listed with `extra["fetchable"] = false` and a
    note saying how many, because an artifact list where a third of the entries
    cannot be retrieved is a fact the operator needs before `--fetch`, not
    after.
  * `mlflow://host/models/<name>` lists the versions of one model and, for each
    version that carries a `run_id`, the run's artifact tree through
    `artifacts/list`. Those *are* fetchable, through the tracking server's own
    `get-artifact` endpoint, because the server proxies them.

Limitations, stated:

  * only a bearer token, from `MLFLOW_TRACKING_TOKEN`. Basic auth through
    `MLFLOW_TRACKING_USERNAME` and `MLFLOW_TRACKING_PASSWORD` is not sent,
    because a username and password pair read out of the environment and put on
    a request is exactly the ambient credential behaviour D-80 refuses to have
    happen implicitly. A Databricks workspace token works, being a bearer.
  * `artifacts/list` is not recursive. Directories are followed to a bounded
    depth and a tree deeper than that sets `complete = False`.
  * the artifact listing paginates by `page_token` and that *is* followed here,
    unlike the Hub and GitHub cases, because MLflow returns the token in the
    body where this client can read it.
"""
from __future__ import annotations

import urllib.parse

from .model import (
    MAX_PAGES,
    Connector,
    ConnectorError,
    Discovery,
    Http,
    RemoteArtifact,
    token_with_source,
)
from .registry import register

NAME = "mlflow"
TOKEN_VARIABLES = ("MLFLOW_TRACKING_TOKEN",)
API = "api/2.0/mlflow"
MAX_RESULTS = 200
# How far into a run's artifact tree the directory walk goes. A run is not a
# filesystem and nobody nests model artifacts eight deep; the cap is what stops
# a cycle or a pathological tree from becoming an unbounded request loop.
MAX_DEPTH = 6
# Schemes the tracking server hands back as a model's storage location that
# this tool has no way to GET. Listed, marked, and counted in the notes.
UNFETCHABLE_SCHEMES = ("s3", "gs", "dbfs", "abfss", "wasbs", "azureml", "file", "runs", "models", "ftp")


def accepts(uri: str) -> bool:
    return uri.lower().startswith(("mlflow://", "mlflow+https://"))


def _parse(uri: str) -> tuple[str, str | None, str | None]:
    """`(tracking_base, model_name, version)`.

    `mlflow://host[:port][/prefix]` is the server. `.../models/<name>` narrows
    to one registered model and `.../models/<name>/<version>` to one version of
    it. A path that is not the `models` form is treated as a prefix the
    tracking server is mounted under, which is how MLflow behind an ingress is
    usually reachable.
    """
    remainder = uri.split("://", 1)[1].strip("/")
    if not remainder:
        raise ConnectorError(f"{uri!r} names no tracking server")
    parts = remainder.split("/")
    host = parts[0]
    rest = parts[1:]
    name: str | None = None
    version: str | None = None
    if "models" in rest:
        index = rest.index("models")
        prefix = "/".join(rest[:index])
        if len(rest) > index + 1:
            name = rest[index + 1]
        if len(rest) > index + 2:
            version = rest[index + 2]
    else:
        prefix = "/".join(rest)
    base = f"https://{host}" + (f"/{prefix}" if prefix else "")
    return base.rstrip("/"), name, version


def _headers() -> tuple[dict[str, str], str | None]:
    token, variable = token_with_source(*TOKEN_VARIABLES)
    return ({"Authorization": f"Bearer {token}"} if token else {}), variable


def discover(uri: str, *, http: Http, revision: str | None = None) -> Discovery:
    base, name, version = _parse(uri)
    if revision and name:
        version = revision
    headers, variable = _headers()
    notes: list[str] = []
    complete = True

    if name is None:
        artifacts, complete, extra_notes = _registered_models(http, base, headers)
        notes.extend(extra_notes)
    else:
        artifacts, complete, extra_notes = _model_version_artifacts(http, base, headers, name, version)
        notes.extend(extra_notes)

    notes.append(f"listed as {'the token in ' + variable if variable else 'an anonymous caller'}")
    notes.append(
        "MLflow publishes no digest for an artifact: every entry here has declared_sha256 empty, so a fetch "
        "measures the bytes and has nothing to compare them against (design note D-90)"
    )
    notes.append(
        "only MLFLOW_TRACKING_TOKEN is read. A username and password pair in the environment is deliberately "
        "not picked up (design note D-90b)"
    )

    return Discovery(
        source=f"{NAME}:{base}" + (f"/models/{name}" if name else ""),
        artifacts=tuple(artifacts),
        complete=complete,
        hosts_contacted=tuple(http.hosts),
        notes=tuple(notes),
        revision=version,
    )


def _registered_models(
    http: Http, base: str, headers: dict[str, str]
) -> tuple[list[RemoteArtifact], bool, list[str]]:
    artifacts: list[RemoteArtifact] = []
    notes: list[str] = []
    token: str | None = None
    complete = True
    unfetchable = 0

    for page in range(MAX_PAGES):
        query = {"max_results": str(MAX_RESULTS)}
        if token:
            query["page_token"] = token
        url = f"{base}/{API}/registered-models/search?" + urllib.parse.urlencode(query)
        payload = http.get_json(url, headers)
        if not isinstance(payload, dict):
            raise ConnectorError(f"{url} did not return a search result")
        for model in payload.get("registered_models") or []:
            if not isinstance(model, dict):
                continue
            model_name = str(model.get("name") or "")
            for latest in model.get("latest_versions") or [{}]:
                source = str(latest.get("source") or "") if isinstance(latest, dict) else ""
                fetchable = source.lower().startswith("https://")
                if not fetchable:
                    unfetchable += 1
                artifacts.append(
                    RemoteArtifact(
                        path=f"{model_name}/{latest.get('version', 'latest')}" if isinstance(latest, dict)
                        else model_name,
                        uri=source,
                        size_bytes=None,
                        declared_sha256=None,
                        revision=str(latest.get("version")) if isinstance(latest, dict) and latest.get("version") else None,
                        source=NAME,
                        extra={
                            "kind": "registered_model_version",
                            "model": model_name,
                            "stage": latest.get("current_stage") if isinstance(latest, dict) else None,
                            "run_id": latest.get("run_id") if isinstance(latest, dict) else None,
                            "fetchable": fetchable,
                        },
                    )
                )
        token = payload.get("next_page_token") or None
        if not token:
            break
        if page == MAX_PAGES - 1:
            complete = False
            notes.append(f"stopped at the {MAX_PAGES} page cap with a page token still outstanding")

    if unfetchable:
        notes.append(
            f"{unfetchable} of {len(artifacts)} model version(s) are stored at a location this tool cannot GET "
            f"(one of {', '.join(UNFETCHABLE_SCHEMES[:5])}...); they carry extra.fetchable false and --fetch "
            "will report ACT-CON-001 for each"
        )
    notes.append(
        "a registered model is a name and a pointer, not a file: this listing enumerates the registry, and the "
        "artifacts of a version are listed by naming it (mlflow://host/models/<name>)"
    )
    return artifacts, complete, notes


def _model_version_artifacts(
    http: Http, base: str, headers: dict[str, str], name: str, version: str | None
) -> tuple[list[RemoteArtifact], bool, list[str]]:
    notes: list[str] = []
    query = {"filter": f"name='{name}'", "max_results": str(MAX_RESULTS)}
    url = f"{base}/{API}/model-versions/search?" + urllib.parse.urlencode(query)
    payload = http.get_json(url, headers)
    if not isinstance(payload, dict):
        raise ConnectorError(f"{url} did not return a version search result")
    versions = [row for row in payload.get("model_versions") or [] if isinstance(row, dict)]
    if version is not None:
        versions = [row for row in versions if str(row.get("version")) == str(version)]
        if not versions:
            raise ConnectorError(f"{name} has no version {version} on this tracking server")

    artifacts: list[RemoteArtifact] = []
    complete = True
    for row in versions:
        run_id = row.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            notes.append(f"version {row.get('version')} carries no run_id, so its artifacts cannot be listed")
            complete = False
            continue
        found, run_complete, run_notes = _run_artifacts(http, base, headers, run_id, name, str(row.get("version")))
        artifacts.extend(found)
        complete = complete and run_complete
        notes.extend(run_notes)
    return artifacts, complete, notes


def _run_artifacts(
    http: Http, base: str, headers: dict[str, str], run_id: str, model: str, version: str
) -> tuple[list[RemoteArtifact], bool, list[str]]:
    """Walk a run's artifact tree, breadth first, to `MAX_DEPTH`."""
    artifacts: list[RemoteArtifact] = []
    notes: list[str] = []
    complete = True
    frontier: list[tuple[str, int]] = [("", 0)]
    requests = 0

    while frontier:
        path, depth = frontier.pop(0)
        page_token: str | None = None
        while True:
            requests += 1
            if requests > MAX_PAGES:
                complete = False
                notes.append(
                    f"run {run_id}: stopped after {MAX_PAGES} artifact requests; the listing is a prefix of the run"
                )
                return artifacts, complete, notes
            query = {"run_id": run_id}
            if path:
                query["path"] = path
            if page_token:
                query["page_token"] = page_token
            url = f"{base}/{API}/artifacts/list?" + urllib.parse.urlencode(query)
            payload = http.get_json(url, headers)
            if not isinstance(payload, dict):
                raise ConnectorError(f"{url} did not return an artifact listing")
            for entry in payload.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                entry_path = str(entry.get("path") or "")
                if not entry_path:
                    continue
                if entry.get("is_dir"):
                    if depth + 1 > MAX_DEPTH:
                        complete = False
                        notes.append(
                            f"run {run_id}: {entry_path} is deeper than the {MAX_DEPTH} level walk and was not "
                            "descended into"
                        )
                        continue
                    frontier.append((entry_path, depth + 1))
                    continue
                size = entry.get("file_size")
                artifacts.append(
                    RemoteArtifact(
                        path=f"{model}/{version}/{entry_path}",
                        uri=f"{base}/get-artifact?" + urllib.parse.urlencode(
                            {"path": entry_path, "run_id": run_id}
                        ),
                        size_bytes=int(size) if isinstance(size, int | str) and str(size).isdigit() else None,
                        # Design note D-90: the server states a size and never a digest.
                        declared_sha256=None,
                        revision=version,
                        source=NAME,
                        extra={"kind": "run_artifact", "run_id": run_id, "model": model,
                               "version": version, "fetchable": True},
                    )
                )
            page_token = payload.get("next_page_token") or None
            if not page_token:
                break
    return artifacts, complete, notes


def headers_for_fetch(_artifact: RemoteArtifact) -> dict[str, str]:
    """The same bearer token on `get-artifact` as on the listing."""
    headers, _variable = _headers()
    return headers


CONNECTOR = register(
    Connector(
        name=NAME,
        summary_key="connector.mlflow",
        needs_network=True,
        discover=discover,
        accepts=accepts,
        fetch_headers=headers_for_fetch,
    )
)
