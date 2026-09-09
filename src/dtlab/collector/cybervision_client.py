"""Strict read-only client for documented Cisco Cyber Vision APIs."""

from __future__ import annotations

import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.utils import parse_header_links

from dtlab.collector.credentials import load_new_ui_token, load_token

CLASSIC_PREFIX = "/api/3.0"
NEW_UI_PREFIX = "/cvapi/v1"
_SENSITIVE_PARAM = re.compile(
    r"(?:token|password|secret|authorization|credential|api[_-]?key)", re.IGNORECASE
)


def _safe_query_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Copy query parameters and serialize booleans as the API expects."""

    result: dict[str, Any] = {}
    for key, value in (params or {}).items():
        result[str(key)] = ("true" if value else "false") if isinstance(value, bool) else value
    return result


class CyberVisionError(RuntimeError):
    """Base Cyber Vision collector error with a non-secret diagnostic code."""

    def __init__(self, code: str, message: str, *, status_code: int | None = None):
        self.code = code
        self.status_code = status_code
        super().__init__(message)


class CyberVisionFeatureUnavailable(CyberVisionError):
    """A documented optional/licensed feature is not available."""


@dataclass(frozen=True)
class CyberVisionConfig:
    base_url: str
    tls_sha256: str | None = None
    ca_bundle: str | Path | None = None
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 30.0
    page_size: int = 200
    max_pages: int = 500

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("base_url deve essere un'origine HTTPS senza credenziali.")
        if not self.ca_bundle and not self.tls_sha256:
            raise ValueError("Configurare ca_bundle oppure tls_sha256.")
        if self.tls_sha256:
            normalized = self.tls_sha256.replace(":", "").lower()
            if not re.fullmatch(r"[a-f0-9]{64}", normalized):
                raise ValueError("tls_sha256 deve essere un fingerprint SHA-256.")
            object.__setattr__(self, "tls_sha256", normalized)
        if self.page_size < 1 or self.page_size > 1000:
            raise ValueError("page_size deve essere compreso fra 1 e 1000.")
        if self.max_pages < 1:
            raise ValueError("max_pages deve essere positivo.")


class _PinnedFingerprintAdapter(HTTPAdapter):
    """Requests adapter that authenticates a self-signed peer by SHA-256 fingerprint."""

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **kwargs):
        kwargs["assert_fingerprint"] = self.fingerprint
        kwargs["cert_reqs"] = ssl.CERT_NONE
        return super().init_poolmanager(connections, maxsize, block=block, **kwargs)

    def cert_verify(self, conn, url, verify, cert) -> None:
        conn.cert_reqs = ssl.CERT_NONE
        conn.ca_certs = None
        conn.ca_cert_dir = None
        conn.assert_fingerprint = self.fingerprint


def _extract_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, Mapping):
        raise CyberVisionError("invalid_payload", "La risposta paginata non è un oggetto.")
    for key in ("items", "content", "results", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, Mapping):
            for nested_key in ("items", "content", "results"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return nested
    raise CyberVisionError(
        "invalid_payload",
        "La risposta paginata non contiene una lista documentata.",
    )


def _record_key(record: Any) -> str:
    if isinstance(record, Mapping):
        for key in ("id", "deviceId", "componentId", "uuid"):
            value = record.get(key)
            if value is not None:
                return f"{key}:{value}"
    return repr(record)


class CyberVisionClient:
    """GET-only client; no generic write method is intentionally exposed."""

    def __init__(
        self,
        config: CyberVisionConfig,
        *,
        token_provider: Callable[[], str] = load_token,
        new_ui_token_provider: Callable[[], str] = load_new_ui_token,
        session: requests.Session | None = None,
    ):
        self.config = config
        self._token_provider = token_provider
        self._new_ui_token_provider = new_ui_token_provider
        self._session = session or requests.Session()
        if session is None:
            self._session.trust_env = False
            if config.tls_sha256 and not config.ca_bundle:
                self._session.mount(
                    config.base_url.rstrip("/") + "/",
                    _PinnedFingerprintAdapter(config.tls_sha256),
                )

    @property
    def timeout(self) -> tuple[float, float]:
        return (
            self.config.connect_timeout_seconds,
            self.config.read_timeout_seconds,
        )

    def _url(self, path: str, *, api: str) -> str:
        if not path.startswith("/") or ".." in path or "://" in path:
            raise CyberVisionError("invalid_path", "Percorso API non valido.")
        if api == "classic":
            prefix = CLASSIC_PREFIX
        elif api == "new_ui":
            prefix = NEW_UI_PREFIX
        else:
            raise CyberVisionError("invalid_api", "Famiglia API non supportata.")
        return self.config.base_url.rstrip("/") + prefix + path

    def _verify_value(self) -> bool | str:
        if self.config.ca_bundle:
            return str(self.config.ca_bundle)
        return False

    def _get_json_response(
        self,
        path: str,
        *,
        api: str = "classic",
        params: Mapping[str, Any] | None = None,
    ) -> tuple[Any, requests.Response]:
        """Perform one authenticated JSON GET and retain safe response metadata."""

        safe_params = _safe_query_params(params)
        if any(_SENSITIVE_PARAM.search(str(key)) for key in safe_params):
            raise CyberVisionError(
                "sensitive_parameter",
                "I segreti devono essere passati solo tramite x-token-id.",
            )
        provider = self._new_ui_token_provider if api == "new_ui" else self._token_provider
        try:
            token = provider()
        except Exception as exc:
            raise CyberVisionError(
                "credential_unavailable",
                "Token Cyber Vision read-only non disponibile.",
            ) from exc
        token = token.strip()
        if not token:
            raise CyberVisionError(
                "credential_unavailable",
                "Token Cyber Vision read-only non disponibile.",
            )

        url = self._url(path, api=api)
        try:
            response = self._session.get(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "DTLabCollector/2.0",
                    "x-token-id": token,
                },
                params=safe_params,
                timeout=self.timeout,
                verify=self._verify_value(),
                allow_redirects=False,
            )
        except requests.exceptions.Timeout as exc:
            raise CyberVisionError("timeout", "Timeout Cyber Vision.") from exc
        except requests.exceptions.SSLError as exc:
            raise CyberVisionError(
                "tls_verification_failed",
                "Certificato o fingerprint Cyber Vision non valido.",
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise CyberVisionError(
                "connection_failed",
                "Connessione Cyber Vision non riuscita.",
            ) from exc

        if 300 <= response.status_code < 400:
            raise CyberVisionError(
                "unexpected_redirect",
                "Cyber Vision ha restituito un redirect inatteso.",
                status_code=response.status_code,
            )
        if response.status_code == 402:
            raise CyberVisionFeatureUnavailable(
                "feature_unlicensed",
                "Funzione Cyber Vision non licenziata.",
                status_code=402,
            )
        if response.status_code == 401:
            raise CyberVisionError(
                "authentication_failed",
                "Token Cyber Vision non valido o scaduto.",
                status_code=401,
            )
        if response.status_code == 403:
            raise CyberVisionError(
                "permission_denied",
                "Il token Cyber Vision non ha il permesso Read richiesto.",
                status_code=403,
            )
        if response.status_code == 404:
            raise CyberVisionFeatureUnavailable(
                "endpoint_unavailable",
                "Endpoint non disponibile in questa versione Cyber Vision.",
                status_code=404,
            )
        if response.status_code == 429:
            raise CyberVisionError(
                "rate_limited",
                "Cyber Vision ha applicato un limite di richieste.",
                status_code=429,
            )
        if response.status_code >= 500:
            raise CyberVisionError(
                "server_error",
                f"Cyber Vision ha restituito HTTP {response.status_code}.",
                status_code=response.status_code,
            )
        if response.status_code >= 400:
            raise CyberVisionError(
                "http_error",
                f"Cyber Vision ha restituito HTTP {response.status_code}.",
                status_code=response.status_code,
            )
        try:
            payload = response.json()
        except (ValueError, requests.exceptions.JSONDecodeError) as exc:
            raise CyberVisionError(
                "invalid_json",
                "Cyber Vision non ha restituito JSON valido.",
                status_code=response.status_code,
            ) from exc
        return payload, response

    def get_json(
        self,
        path: str,
        *,
        api: str = "classic",
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Perform one authenticated JSON GET with bounded timeouts."""

        payload, _response = self._get_json_response(path, api=api, params=params)
        return payload

    def classic_get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        return self.get_json(path, api="classic", params=params)

    def new_ui_get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        return self.get_json(path, api="new_ui", params=params)

    def _new_ui_next_cursor(
        self,
        response: requests.Response,
        *,
        expected_url: str,
    ) -> str | None:
        """Return a validated cursor from Link rel=next without exposing its value."""

        link_header = response.headers.get("Link")
        if not link_header:
            return None
        try:
            links = parse_header_links(link_header.rstrip(">").replace(">,<", ">, <"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise CyberVisionError(
                "invalid_pagination_link",
                "Header di paginazione New UI non valido.",
            ) from exc
        next_links = [
            link for link in links if "next" in str(link.get("rel") or "").lower().split()
        ]
        if not next_links:
            return None
        if len(next_links) != 1 or not next_links[0].get("url"):
            raise CyberVisionError(
                "invalid_pagination_link",
                "Header di paginazione New UI ambiguo.",
            )

        expected = urlsplit(expected_url)
        candidate = urlsplit(urljoin(expected_url, str(next_links[0]["url"])))
        try:
            expected_port = expected.port or 443
            candidate_port = candidate.port or 443
        except ValueError as exc:
            raise CyberVisionError(
                "unsafe_pagination_link",
                "Destinazione di paginazione New UI non autorizzata.",
            ) from exc
        if (
            candidate.scheme.lower() != expected.scheme.lower()
            or (candidate.hostname or "").lower() != (expected.hostname or "").lower()
            or candidate_port != expected_port
            or candidate.username is not None
            or candidate.password is not None
            or candidate.fragment
            or not candidate.path.startswith(NEW_UI_PREFIX + "/")
            or candidate.path != expected.path
        ):
            raise CyberVisionError(
                "unsafe_pagination_link",
                "Destinazione di paginazione New UI non autorizzata.",
            )

        cursors = parse_qs(candidate.query, keep_blank_values=True).get("cursor", [])
        if len(cursors) != 1 or not cursors[0]:
            raise CyberVisionError(
                "invalid_pagination_link",
                "Cursor di paginazione New UI assente o ambiguo.",
            )
        return cursors[0]

    def new_ui_pages(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Collect a cursor-paginated New UI envelope using validated GET links."""

        base_params = dict(params or {})
        page_params = dict(base_params)
        seen_cursors: set[str] = set()
        initial_cursor = page_params.get("cursor")
        if initial_cursor is not None:
            seen_cursors.add(str(initial_cursor))
        expected_url = self._url(path, api="new_ui")
        first_envelope: dict[str, Any] | None = None
        all_items: list[Any] = []

        for _page in range(1, self.config.max_pages + 1):
            payload, response = self._get_json_response(
                path,
                api="new_ui",
                params=page_params,
            )
            if not isinstance(payload, Mapping) or not isinstance(payload.get("items"), list):
                raise CyberVisionError(
                    "invalid_payload",
                    "La risposta New UI paginata non contiene items.",
                )
            if first_envelope is None:
                first_envelope = {
                    key: value for key, value in payload.items() if "cursor" not in str(key).lower()
                }
            all_items.extend(payload["items"])

            cursor = self._new_ui_next_cursor(response, expected_url=expected_url)
            if cursor is None:
                first_envelope["items"] = all_items
                return first_envelope
            if cursor in seen_cursors:
                raise CyberVisionError(
                    "pagination_cursor_repeated",
                    "Cyber Vision ha ripetuto un cursor di paginazione New UI.",
                )
            seen_cursors.add(cursor)
            page_params = {**base_params, "cursor": cursor}

        raise CyberVisionError(
            "pagination_limit",
            f"Limite di {self.config.max_pages} pagine raggiunto per {path}.",
        )

    def classic_pages(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> list[Any]:
        """Read Classic page/size endpoints until an empty or duplicate page."""

        base_params = dict(params or {})
        results: list[Any] = []
        seen: set[str] = set()
        for page in range(1, self.config.max_pages + 1):
            page_params = {
                **base_params,
                "page": page,
                "size": self.config.page_size,
            }
            items = _extract_items(self.classic_get(path, params=page_params))
            if not items:
                return results
            new_items = []
            for item in items:
                key = _record_key(item)
                if key not in seen:
                    seen.add(key)
                    new_items.append(item)
            results.extend(new_items)
            if len(items) < self.config.page_size or not new_items:
                return results
        raise CyberVisionError(
            "pagination_limit",
            f"Limite di {self.config.max_pages} pagine raggiunto per {path}.",
        )

    def device_risk_score(self, device_id: Any) -> Any:
        safe_id = quote(str(device_id), safe="")
        return self.classic_get(f"/devices/{safe_id}/riskScore")

    def device_vulnerabilities(self, device_id: Any) -> list[Any]:
        safe_id = quote(str(device_id), safe="")
        return self.classic_pages(f"/devices/{safe_id}/vulnerabilities")

    def baseline_differences(self, baseline_id: Any) -> list[Any]:
        safe_id = quote(str(baseline_id), safe="")
        return self.classic_pages(f"/baselines/{safe_id}/differences")

    def sensor_stats(self, sensor_id: Any, *, period: str = "2h") -> Any:
        if period not in {"2h", "24h", "7d", "30d", "180d", "360d"}:
            raise CyberVisionError("invalid_period", "Periodo statistiche sensore non valido.")
        safe_id = quote(str(sensor_id), safe="")
        return self.classic_get(f"/sensors/{safe_id}/stats", params={"p": period})

    def sensor_details(self, sensor_id: Any) -> Any:
        safe_id = quote(str(sensor_id), safe="")
        return self.classic_get(f"/sensors/{safe_id}")
