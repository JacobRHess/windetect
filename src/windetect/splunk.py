"""Minimal Splunk client for the throwaway lab node.

The client bootstraps everything the replay needs over REST - the index,
search-time props (KV_MODE=json so fixture fields are searchable), and an
HEC input with its token. Bootstrapping is idempotent: against the docker
lab the conf files under lab/splunk already provide all three and the
client simply adopts them; against the CI service container, which mounts
no conf, the client creates them at runtime. Same code path, same result.

Credentials are the throwaway dev ones from lab/docker-compose.yml; the lab
node is disposable and never leaves localhost. TLS verification defaults to
on, and is skipped automatically only when every endpoint is localhost (the
lab container serves a self-signed certificate).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from urllib.parse import quote, urlparse

import requests
import urllib3

from windetect.schema import SOURCETYPES

DEFAULT_REST_URL = "https://localhost:8089"
DEFAULT_HEC_URL = "https://localhost:8088"
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "windetect_dev_2026"  # noqa: S105  # nosec B105
DEFAULT_INDEX = "windetect"

ENV_REST_URL = "WD_SPLUNK_URL"
ENV_HEC_URL = "WD_SPLUNK_HEC_URL"
ENV_USER = "WD_SPLUNK_USER"
ENV_PASSWORD = "WD_SPLUNK_PASSWORD"  # noqa: S105  # nosec B105
ENV_INDEX = "WD_SPLUNK_INDEX"
ENV_VERIFY = "WD_SPLUNK_VERIFY"

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_HEC_BATCH = 500


class SplunkError(RuntimeError):
    """The lab Splunk refused a request or never became searchable."""


def _is_local(url: str) -> bool:
    return urlparse(url).hostname in _LOCAL_HOSTS


@dataclass(frozen=True)
class SplunkConfig:
    rest_url: str = DEFAULT_REST_URL
    hec_url: str = DEFAULT_HEC_URL
    username: str = DEFAULT_USER
    password: str = DEFAULT_PASSWORD
    index: str = DEFAULT_INDEX
    # None = automatic: verify unless every endpoint is localhost (the lab's
    # self-signed cert). Never silently skip verification for a remote Splunk.
    verify: bool | None = None

    @property
    def tls_verify(self) -> bool:
        if self.verify is not None:
            return self.verify
        return not (_is_local(self.rest_url) and _is_local(self.hec_url))


def _verify_from_env() -> bool | None:
    raw = os.environ.get(ENV_VERIFY, "").strip().lower()
    if not raw:
        return None
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    raise SplunkError(f"{ENV_VERIFY} must be a boolean (true/false), got {raw!r}")


def config_from_env() -> SplunkConfig:
    defaults = SplunkConfig()
    return SplunkConfig(
        rest_url=os.environ.get(ENV_REST_URL, defaults.rest_url),
        hec_url=os.environ.get(ENV_HEC_URL, defaults.hec_url),
        username=os.environ.get(ENV_USER, defaults.username),
        password=os.environ.get(ENV_PASSWORD, defaults.password),
        index=os.environ.get(ENV_INDEX, defaults.index),
        verify=_verify_from_env(),
    )


def hec_batch(events: list[dict[str, Any]], *, run_tag: str, index: str, source: str) -> str:
    """Build the NDJSON HEC body for one fixture replay."""
    lines = []
    for event in events:
        when = datetime.fromisoformat(event["_time"]).timestamp()
        record = {
            "time": when,
            "host": event["Computer"],
            "source": source,
            "sourcetype": event["sourcetype"],
            "index": index,
            "event": {**event, "wd_run": run_tag},
        }
        lines.append(json.dumps(record))
    return "\n".join(lines)


def parse_search_export(body: str) -> list[dict[str, Any]]:
    """Pull result rows out of an NDJSON /search/jobs/export body."""
    rows: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if not isinstance(record, dict) or record.get("preview"):
            continue
        result = record.get("result")
        if result is None:
            continue
        if not isinstance(result, dict):
            raise SplunkError(f"malformed search export row: {record!r}")
        rows.append(cast("dict[str, Any]", result))
    return rows


def _error_text(body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body[:300]
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if isinstance(messages, list) and messages:
        return "; ".join(str(m.get("text", "")) for m in messages if isinstance(m, dict))
    return body[:300]


class SplunkClient:
    def __init__(self, config: SplunkConfig, *, timeout: float = 30.0) -> None:
        self.config = config
        self._timeout = timeout
        verify = config.tls_verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._session = requests.Session()
        self._session.auth = (config.username, config.password)
        self._session.verify = verify
        # Session auth would overwrite the per-request HEC token header with
        # Basic credentials, so ingest gets its own auth-less session.
        self._hec_session = requests.Session()
        self._hec_session.verify = verify
        self._hec_token: str | None = None

    def close(self) -> None:
        self._session.close()
        self._hec_session.close()

    def __enter__(self) -> SplunkClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def index(self) -> str:
        return self.config.index

    def bootstrap(self) -> None:
        self._ensure_index()
        self._ensure_props()
        self._hec_token = self._ensure_hec_token()

    def send_events(self, events: list[dict[str, Any]], *, run_tag: str, source: str) -> int:
        if self._hec_token is None:
            raise SplunkError("bootstrap() before send_events()")
        for start in range(0, len(events), _HEC_BATCH):
            batch = events[start : start + _HEC_BATCH]
            body = hec_batch(batch, run_tag=run_tag, index=self.config.index, source=source)
            response = self._hec_session.post(
                f"{self.config.hec_url}/services/collector/event",
                headers={"Authorization": f"Splunk {self._hec_token}"},
                data=body.encode("utf-8"),
                timeout=self._timeout,
            )
            if response.status_code != 200:
                raise SplunkError(
                    f"HEC ingest failed ({response.status_code}): {response.text[:300]}"
                )
            try:
                ack = json.loads(response.text)
            except json.JSONDecodeError as exc:
                raise SplunkError(f"HEC returned non-JSON ack: {response.text[:300]}") from exc
            if ack.get("code") != 0:
                raise SplunkError(f"HEC rejected batch: {ack!r}")
        return len(events)

    def count_events(self, run_tag: str) -> int:
        rows = self.oneshot_search(
            f'index={self.config.index} wd_run="{run_tag}" | stats count as count'
        )
        if not rows:
            return 0
        return int(rows[0].get("count", 0))

    def wait_indexed(self, run_tag: str, expected: int, *, timeout: float = 90.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.count_events(run_tag) >= expected:
                return
            time.sleep(2.0)
        seen = self.count_events(run_tag)
        raise SplunkError(
            f"only {seen}/{expected} events tagged {run_tag!r} became searchable within {timeout}s"
        )

    def oneshot_search(
        self, spl: str, *, earliest: str | None = None, latest: str | None = None
    ) -> list[dict[str, Any]]:
        # The export endpoint parses a bare first token as a command name, so
        # keyword searches need the explicit search command.
        if not spl.lstrip().startswith(("|", "search ")):
            spl = f"search {spl}"
        data = {"search": spl, "output_mode": "json"}
        if earliest is not None:
            data["earliest_time"] = earliest
        if latest is not None:
            data["latest_time"] = latest
        response = self._session.post(
            f"{self.config.rest_url}/services/search/jobs/export",
            data=data,
            timeout=self._timeout,
        )
        if response.status_code != 200:
            raise SplunkError(
                f"Splunk search failed ({response.status_code}): {_error_text(response.text)}"
            )
        try:
            return parse_search_export(response.text)
        except json.JSONDecodeError as exc:
            raise SplunkError(
                f"search returned non-JSON ({response.status_code}): {response.text[:300]}"
            ) from exc

    def _ensure_index(self) -> None:
        if self._rest("GET", f"/services/data/indexes/{self.config.index}") is not None:
            return
        created = self._rest("POST", "/services/data/indexes", data={"name": self.config.index})
        if created is None:
            raise SplunkError(f"could not create index {self.config.index}")

    def _ensure_props(self) -> None:
        for sourcetype in SOURCETYPES:
            stanza = quote(sourcetype, safe="")
            base = f"/servicesNS/nobody/search/configs/conf-props/{stanza}"
            fields = {"KV_MODE": "json", "SHOULD_LINEMERGE": "false"}
            if self._rest("GET", base) is None:
                created = self._rest(
                    "POST",
                    "/servicesNS/nobody/search/configs/conf-props",
                    data={"name": sourcetype, **fields},
                )
                if created is None:
                    raise SplunkError(f"could not create props stanza for {sourcetype}")
            else:
                self._rest("POST", base, data=fields)

    def _ensure_hec_token(self) -> str:
        owner = quote(self.config.username, safe="")
        entry = f"/servicesNS/{owner}/splunk_httpinput/data/inputs/http/{self.config.index}"
        payload = self._rest("GET", entry)
        if payload is not None:
            return _extract_token(payload, entry)
        created = self._rest(
            "POST",
            f"/servicesNS/{owner}/splunk_httpinput/data/inputs/http",
            data={"name": self.config.index, "index": self.config.index, "disabled": "0"},
        )
        if created is None:
            raise SplunkError("could not create HEC input")
        return _extract_token(created, entry)

    def _rest(self, method: str, path: str, **kwargs: Any) -> dict[str, Any] | None:
        response = self._session.request(
            method,
            f"{self.config.rest_url}{path}",
            params={"output_mode": "json"},
            timeout=self._timeout,
            **kwargs,
        )
        if response.status_code == 404:
            return None
        try:
            payload = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise SplunkError(
                f"{method} {path} returned non-JSON ({response.status_code})"
            ) from exc
        if response.status_code >= 400:
            raise SplunkError(
                f"{method} {path} failed ({response.status_code}): {_error_text(response.text)}"
            )
        return cast("dict[str, Any]", payload)


def _extract_token(payload: dict[str, Any], entry: str) -> str:
    entries = payload.get("entry")
    if isinstance(entries, list) and entries:
        token = entries[0].get("content", {}).get("token")
        if isinstance(token, str) and token:
            return token
    raise SplunkError(f"no HEC token in response for {entry}")
