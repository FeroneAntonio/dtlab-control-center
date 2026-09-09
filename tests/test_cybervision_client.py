from __future__ import annotations

from typing import Any

import pytest
import requests

from dtlab.collector.cybervision_client import (
    CyberVisionClient,
    CyberVisionConfig,
    CyberVisionError,
    CyberVisionFeatureUnavailable,
)


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, responses: list[Any]):
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def config() -> CyberVisionConfig:
    return CyberVisionConfig(
        base_url="https://cybervision.internal",
        tls_sha256="a" * 64,
        page_size=2,
        max_pages=3,
    )


def test_get_uses_documented_classic_path_and_token_header() -> None:
    session = FakeSession([FakeResponse(200, {"major": 5, "minor": 5})])
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=session,
    )

    payload = client.classic_get("/version")

    assert payload == {"major": 5, "minor": 5}
    assert session.calls[0]["url"] == ("https://cybervision.internal/api/3.0/version")
    assert session.calls[0]["headers"]["x-token-id"] == "vault-token"
    assert session.calls[0]["allow_redirects"] is False
    assert session.calls[0]["timeout"] == (5.0, 30.0)


def test_new_ui_uses_its_separate_read_only_token() -> None:
    session = FakeSession([FakeResponse(200, {"items": []})])
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "classic-vault-token",
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    payload = client.new_ui_get("/assets", params={"max": 1})

    assert payload == {"items": []}
    assert session.calls[0]["url"] == ("https://cybervision.internal/cvapi/v1/assets")
    assert session.calls[0]["headers"]["x-token-id"] == "new-ui-vault-token"
    assert session.calls[0]["params"] == {"max": 1}


def test_query_booleans_are_serialized_lowercase() -> None:
    session = FakeSession([FakeResponse(200, {"items": []})])
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    client.new_ui_get(
        "/assets",
        params={"vulnerable": True, "hasActiveAlerts": False},
    )

    assert session.calls[0]["params"] == {
        "vulnerable": "true",
        "hasActiveAlerts": "false",
    }


def test_new_ui_pagination_follows_validated_link_and_preserves_first_metadata() -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "centerId": "center-1",
                    "cursor": "body-cursor-secret",
                    "items": [{"id": "asset-1"}],
                    "nextCursor": "body-next-cursor-secret",
                    "pageSize": 1,
                },
                headers={
                    "Link": (
                        "<https://cybervision.internal/cvapi/v1/assets"
                        '?max=2&cursor=cursor-secret>; rel="next"'
                    )
                },
            ),
            FakeResponse(
                200,
                {
                    "centerId": "center-from-later-page",
                    "items": [{"id": "asset-2"}],
                    "pageSize": 1,
                },
            ),
        ]
    )
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    payload = client.new_ui_pages(
        "/assets",
        params={"max": 2, "hasActiveAlerts": True},
    )

    assert payload == {
        "centerId": "center-1",
        "items": [{"id": "asset-1"}, {"id": "asset-2"}],
        "pageSize": 1,
    }
    assert "cursor-secret" not in repr(payload)
    assert "body-cursor-secret" not in repr(payload)
    assert "body-next-cursor-secret" not in repr(payload)
    assert session.calls[0]["params"] == {
        "max": 2,
        "hasActiveAlerts": "true",
    }
    assert session.calls[1]["params"] == {
        "max": 2,
        "hasActiveAlerts": "true",
        "cursor": "cursor-secret",
    }


@pytest.mark.parametrize(
    "link",
    [
        "<http://cybervision.internal/cvapi/v1/assets?cursor=hidden>; rel=next",
        "<https://other.internal/cvapi/v1/assets?cursor=hidden>; rel=next",
        "<https://cybervision.internal:444/cvapi/v1/assets?cursor=hidden>; rel=next",
        "<https://user:pass@cybervision.internal/cvapi/v1/assets?cursor=hidden>; rel=next",
        "<https://cybervision.internal/api/3.0/assets?cursor=hidden>; rel=next",
        "<https://cybervision.internal/cvapi/v1/networks?cursor=hidden>; rel=next",
    ],
)
def test_new_ui_pagination_rejects_unsafe_next_destinations(link: str) -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {"items": [{"id": "asset-1"}]},
                headers={"Link": link},
            )
        ]
    )
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    with pytest.raises(CyberVisionError) as caught:
        client.new_ui_pages("/assets", params={"max": 2})

    assert caught.value.code == "unsafe_pagination_link"
    assert "hidden" not in str(caught.value)
    assert len(session.calls) == 1


def test_new_ui_pagination_rejects_repeated_cursor_without_exposing_it() -> None:
    repeated_link = '</cvapi/v1/assets?max=1&cursor=do-not-expose>; rel="next"'
    session = FakeSession(
        [
            FakeResponse(
                200,
                {"items": [{"id": "asset-1"}]},
                headers={"Link": repeated_link},
            ),
            FakeResponse(
                200,
                {"items": [{"id": "asset-2"}]},
                headers={"Link": repeated_link},
            ),
        ]
    )
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    with pytest.raises(CyberVisionError) as caught:
        client.new_ui_pages("/assets", params={"max": 1})

    assert caught.value.code == "pagination_cursor_repeated"
    assert "do-not-expose" not in str(caught.value)
    assert len(session.calls) == 2


def test_new_ui_pagination_honors_max_pages() -> None:
    responses = []
    for page in range(1, 4):
        responses.append(
            FakeResponse(
                200,
                {"items": [{"id": f"asset-{page}"}]},
                headers={
                    "Link": (f"</cvapi/v1/assets?max=1&cursor=private-cursor-{page}>; rel=next")
                },
            )
        )
    session = FakeSession(responses)
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    with pytest.raises(CyberVisionError) as caught:
        client.new_ui_pages("/assets", params={"max": 1})

    assert caught.value.code == "pagination_limit"
    assert "private-cursor" not in str(caught.value)
    assert len(session.calls) == 3


def test_new_ui_pagination_requires_one_nonempty_cursor() -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {"items": [{"id": "asset-1"}]},
                headers={"Link": ("</cvapi/v1/assets?cursor=&cursor=hidden>; rel=next")},
            )
        ]
    )
    client = CyberVisionClient(
        config(),
        new_ui_token_provider=lambda: "new-ui-vault-token",
        session=session,
    )

    with pytest.raises(CyberVisionError) as caught:
        client.new_ui_pages("/assets")

    assert caught.value.code == "invalid_pagination_link"
    assert "hidden" not in str(caught.value)


def test_client_exposes_no_write_method() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=FakeSession([]),
    )

    assert not hasattr(client, "post")
    assert not hasattr(client, "put")
    assert not hasattr(client, "delete")


def test_authentication_error_never_contains_token() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "super-secret-value",
        session=FakeSession([FakeResponse(401, {"error": "bad token"})]),
    )

    with pytest.raises(CyberVisionError) as caught:
        client.classic_get("/version")

    assert caught.value.code == "authentication_failed"
    assert "super-secret-value" not in str(caught.value)


def test_licensed_feature_402_has_explicit_state() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=FakeSession([FakeResponse(402, {})]),
    )

    with pytest.raises(CyberVisionFeatureUnavailable) as caught:
        client.classic_get("/baselines")

    assert caught.value.code == "feature_unlicensed"


def test_classic_pagination_deduplicates_and_stops_on_short_page() -> None:
    session = FakeSession(
        [
            FakeResponse(200, {"items": [{"id": 1}, {"id": 2}]}),
            FakeResponse(200, {"items": [{"id": 2}, {"id": 3}]}),
            FakeResponse(200, {"items": []}),
        ]
    )
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=session,
    )

    items = client.classic_pages("/devices")

    assert items == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert [call["params"]["page"] for call in session.calls] == [1, 2, 3]
    assert all(call["params"]["size"] == 2 for call in session.calls)


def test_timeout_is_mapped_to_nonsecret_error() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=FakeSession([requests.Timeout("details must not escape")]),
    )

    with pytest.raises(CyberVisionError) as caught:
        client.classic_get("/devices")

    assert caught.value.code == "timeout"
    assert "details must not escape" not in str(caught.value)


@pytest.mark.parametrize("status_code", [500, 502, 503])
def test_server_errors_have_explicit_safe_classification(status_code: int) -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "super-secret-value",
        session=FakeSession([FakeResponse(status_code, {"error": "private backend details"})]),
    )

    with pytest.raises(CyberVisionError) as caught:
        client.sensor_stats("sensor-1", period="2h")

    assert caught.value.code == "server_error"
    assert caught.value.status_code == status_code
    assert f"HTTP {status_code}" in str(caught.value)
    assert "super-secret-value" not in str(caught.value)
    assert "private backend details" not in str(caught.value)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://cybervision.internal",
        "https://user:pass@cybervision.internal",
        "https://cybervision.internal?token=bad",
    ],
)
def test_config_rejects_unsafe_origins(base_url: str) -> None:
    with pytest.raises(ValueError):
        CyberVisionConfig(base_url=base_url, tls_sha256="a" * 64)


def test_sensitive_query_parameter_is_rejected() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=FakeSession([]),
    )

    with pytest.raises(CyberVisionError, match="x-token-id"):
        client.classic_get("/devices", params={"access_token": "bad"})


def test_path_traversal_is_rejected() -> None:
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=FakeSession([]),
    )

    with pytest.raises(CyberVisionError, match="Percorso"):
        client.classic_get("/../admin")


def test_sensor_detail_and_stats_are_get_only_documented_paths() -> None:
    session = FakeSession(
        [
            FakeResponse(200, {"id": "sensor-1"}),
            FakeResponse(200, {"cpu": 10}),
        ]
    )
    client = CyberVisionClient(
        config(),
        token_provider=lambda: "vault-token",
        session=session,
    )

    client.sensor_details("sensor-1")
    client.sensor_stats("sensor-1", period="2h")

    assert session.calls[0]["url"].endswith("/api/3.0/sensors/sensor-1")
    assert session.calls[1]["url"].endswith("/api/3.0/sensors/sensor-1/stats")
    assert session.calls[1]["params"] == {"p": "2h"}
