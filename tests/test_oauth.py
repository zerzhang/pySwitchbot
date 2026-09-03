"""Tests for SwitchBot OAuth helpers."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import ANY, AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import aiohttp
import pytest

from switchbot import (
    OAUTH_AUTHORIZE_URL,
    OAUTH_SCOPE,
    OAUTH_TOKEN_URL,
    SwitchbotAccountConnectionError,
    SwitchbotApiError,
    SwitchbotAuthenticationError,
    build_oauth_authorize_url,
    exchange_oauth_code,
)

CLIENT_ID = "client-id"
REDIRECT_URI = "https://example.com/oauth/callback"
STATE = "oauth-state"


def _mock_session(
    *,
    status: int = 200,
    json_data: Any = None,
    text: str = "",
    json_exception: Exception | None = None,
) -> MagicMock:
    """Create a mocked client session and response."""
    response = MagicMock()
    response.status = status
    response.headers = {"x-request-id": "oauth-request-id"}
    response.text = AsyncMock(return_value=text)
    response.json = AsyncMock(return_value=json_data)
    if json_exception is not None:
        response.json.side_effect = json_exception

    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.return_value.__aenter__ = AsyncMock(return_value=response)
    session.post.return_value.__aexit__ = AsyncMock(return_value=None)
    return session


def test_oauth_production_endpoints() -> None:
    """Test OAuth uses the SwitchBot production endpoints."""
    assert OAUTH_AUTHORIZE_URL == "https://sp.oauth.switchbot.net"
    assert (
        OAUTH_TOKEN_URL == "https://account.api.switchbot.net/merchant/v1/oauth/token"
    )
    assert OAUTH_SCOPE == "api_login"


def test_build_oauth_authorize_url() -> None:
    """Test authorization URL generation."""
    url = build_oauth_authorize_url(CLIENT_ID, REDIRECT_URI, STATE)
    parsed = urlparse(url)

    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == OAUTH_AUTHORIZE_URL
    assert parse_qs(parsed.query) == {
        "client_id": [CLIENT_ID],
        "redirect_uri": [REDIRECT_URI],
        "response_type": ["code"],
        "scope": [OAUTH_SCOPE],
        "state": [STATE],
    }
    assert "client_secret" not in parsed.query
    assert "code_challenge" not in parsed.query


@pytest.mark.asyncio
async def test_exchange_oauth_code() -> None:
    """Test authorization code exchange."""
    token = {
        "access_token": "access-token",
        "refresh_token": "refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_expires_in": 2592000,
    }
    session = _mock_session(json_data=token)

    result = await exchange_oauth_code(
        session,
        CLIENT_ID,
        REDIRECT_URI,
        "authorization-code",
    )

    assert result == token
    session.post.assert_called_once_with(
        OAUTH_TOKEN_URL,
        data={
            "code": "authorization-code",
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
        timeout=ANY,
    )
    assert "client_secret" not in session.post.call_args.kwargs["data"]
    assert "code_verifier" not in session.post.call_args.kwargs["data"]


@pytest.mark.asyncio
async def test_exchange_oauth_code_accepts_string_expiry() -> None:
    """Test a numeric string expiry returned by the token endpoint."""
    token = {
        "access_token": "access-token",
        "expires_in": "3600",
    }
    session = _mock_session(json_data=token)

    assert (
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )
        == token
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        pytest.param({"expires_in": 3600}, id="missing-access-token"),
        pytest.param({"access_token": "access-token"}, id="missing-expires-in"),
        pytest.param(
            {"access_token": "access-token", "expires_in": "invalid"},
            id="invalid-expires-in",
        ),
        pytest.param(
            {"access_token": "access-token", "expires_in": True},
            id="boolean-expires-in",
        ),
    ],
)
async def test_exchange_oauth_code_invalid_token(token: dict[str, Any]) -> None:
    """Test invalid token response data."""
    session = _mock_session(json_data=token)

    with pytest.raises(SwitchbotApiError, match="Invalid token data"):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 499])
async def test_exchange_oauth_code_authentication_error(status: int) -> None:
    """Test a rejected authorization code."""
    session = _mock_session(status=status, text="invalid grant")

    with pytest.raises(SwitchbotAuthenticationError, match=str(status)):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 500, 503])
async def test_exchange_oauth_code_transient_error(status: int) -> None:
    """Test transient token service errors."""
    session = _mock_session(status=status, text="service unavailable")

    with pytest.raises(SwitchbotAccountConnectionError, match=str(status)):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
async def test_exchange_oauth_code_connection_error() -> None:
    """Test token service connection errors."""
    session = MagicMock(spec=aiohttp.ClientSession)
    session.post.side_effect = aiohttp.ClientError("connection failed")

    with pytest.raises(SwitchbotAccountConnectionError, match="connection failed"):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
async def test_exchange_oauth_code_invalid_json() -> None:
    """Test an invalid token service response."""
    session = _mock_session(json_exception=ValueError("invalid json"))

    with pytest.raises(SwitchbotApiError, match="Invalid response"):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
async def test_exchange_oauth_code_invalid_json_shape() -> None:
    """Test a non-object token service response."""
    session = _mock_session(json_data=[])

    with pytest.raises(SwitchbotApiError, match="Invalid response"):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "authorization-code",
        )


@pytest.mark.asyncio
async def test_oauth_debug_logs_exclude_sensitive_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test OAuth debug logs contain stages but no credential values."""
    token = {
        "access_token": "sensitive-access-token",
        "refresh_token": "sensitive-refresh-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_expires_in": 2592000,
    }
    session = _mock_session(json_data=token)
    caplog.set_level(logging.DEBUG, logger="switchbot.oauth")

    build_oauth_authorize_url(CLIENT_ID, REDIRECT_URI, STATE)
    await exchange_oauth_code(
        session,
        CLIENT_ID,
        REDIRECT_URI,
        "sensitive-authorization-code",
    )

    assert "Building SwitchBot OAuth authorization request" in caplog.text
    assert "authorize_host=sp.oauth.switchbot.net" in caplog.text
    assert "redirect_host=example.com" in caplog.text
    assert "token endpoint returned HTTP status 200" in caplog.text
    assert "duration_ms=" in caplog.text
    assert "request_id=oauth-request-id" in caplog.text
    assert (
        "token response fields: "
        "['access_token', 'expires_in', 'refresh_expires_in', 'refresh_token', "
        "'token_type']"
    ) in caplog.text
    assert "token response validated; expires_in=3600" in caplog.text
    assert "refresh_token_present=True" in caplog.text
    assert "refresh_expires_in_present=True" in caplog.text
    for sensitive_value in (
        "sensitive-authorization-code",
        "sensitive-access-token",
        "sensitive-refresh-token",
        "2592000",
        STATE,
    ):
        assert sensitive_value not in caplog.text


@pytest.mark.asyncio
async def test_oauth_error_logs_exclude_response_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test an OAuth error body is summarized but not logged."""
    session = _mock_session(status=400, text="sensitive-provider-error")
    caplog.set_level(logging.DEBUG, logger="switchbot.oauth")

    with pytest.raises(SwitchbotAuthenticationError):
        await exchange_oauth_code(
            session,
            CLIENT_ID,
            REDIRECT_URI,
            "sensitive-authorization-code",
        )

    assert "body_length=24" in caplog.text
    assert "sensitive-provider-error" not in caplog.text
    assert "sensitive-authorization-code" not in caplog.text
