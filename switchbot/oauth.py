"""OAuth helpers for the SwitchBot account API."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from time import monotonic
from typing import Any
from urllib.parse import urlencode, urlsplit

import aiohttp

from .const import (
    SwitchbotAccountConnectionError,
    SwitchbotApiError,
    SwitchbotAuthenticationError,
)

_LOGGER = logging.getLogger(__name__)
_REQUEST_ID_HEADERS = ("x-request-id", "x-amzn-requestid", "cf-ray")

OAUTH_AUTHORIZE_URL = "https://sp.oauth.switchbot.net"
OAUTH_TOKEN_URL = "https://account.api.switchbot.net/merchant/v1/oauth/token"
OAUTH_SCOPE = "api_login"


def _request_id(headers: Mapping[str, str]) -> str | None:
    """Extract a provider request identifier for log correlation."""
    return next(
        (value for name in _REQUEST_ID_HEADERS if (value := headers.get(name))), None
    )


def build_oauth_authorize_url(
    client_id: str,
    redirect_uri: str,
    state: str,
) -> str:
    """Build a SwitchBot OAuth authorization URL."""
    _LOGGER.debug(
        "Building SwitchBot OAuth authorization request; authorize_host=%s "
        "redirect_host=%s",
        urlsplit(OAUTH_AUTHORIZE_URL).hostname,
        urlsplit(redirect_uri).hostname,
    )
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": OAUTH_SCOPE,
            "state": state,
        }
    )
    return f"{OAUTH_AUTHORIZE_URL}?{query}"


async def exchange_oauth_code(
    session: aiohttp.ClientSession,
    client_id: str,
    redirect_uri: str,
    code: str,
) -> dict[str, Any]:
    """Exchange an OAuth authorization code for a SwitchBot access token."""
    started = monotonic()
    _LOGGER.debug(
        "Exchanging SwitchBot OAuth authorization code; token_host=%s",
        urlsplit(OAUTH_TOKEN_URL).hostname,
    )
    token_data: Any = None
    try:
        async with session.post(
            OAUTH_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            status = response.status
            _LOGGER.debug(
                "SwitchBot OAuth token endpoint returned HTTP status %s; "
                "duration_ms=%s request_id=%s",
                status,
                round((monotonic() - started) * 1000),
                _request_id(response.headers) or "unavailable",
            )
            if status >= 400:
                detail = await response.text()
                _LOGGER.debug(
                    "SwitchBot OAuth token endpoint returned an error response; "
                    "body_length=%s",
                    len(detail),
                )
            else:
                try:
                    token_data = await response.json()
                except (aiohttp.ClientError, ValueError, TypeError) as err:
                    raise SwitchbotApiError(
                        "Invalid response from SwitchBot OAuth token API"
                    ) from err
    except (aiohttp.ClientError, TimeoutError) as err:
        raise SwitchbotAccountConnectionError(
            f"Failed to connect to SwitchBot OAuth token API: {err}"
        ) from err

    if 400 <= status < 500 and status != 429:
        raise SwitchbotAuthenticationError(
            f"SwitchBot OAuth token request rejected ({status})"
        )
    if status == 429 or status >= 500:
        raise SwitchbotAccountConnectionError(
            f"SwitchBot OAuth token service unavailable ({status})"
        )
    if not isinstance(token_data, dict):
        raise SwitchbotApiError("Invalid response from SwitchBot OAuth token API")

    token: dict[str, Any] = token_data
    _LOGGER.debug("SwitchBot OAuth token response fields: %s", sorted(token))
    access_token = token.get("access_token")
    expires_in = token.get("expires_in")
    if (
        not isinstance(access_token, str)
        or not access_token
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int | str)
    ):
        raise SwitchbotApiError("Invalid token data from SwitchBot OAuth token API")
    try:
        int(expires_in)
    except ValueError as err:
        raise SwitchbotApiError(
            "Invalid token data from SwitchBot OAuth token API"
        ) from err
    _LOGGER.debug(
        "SwitchBot OAuth token response validated; expires_in=%s "
        "refresh_token_present=%s refresh_expires_in_present=%s",
        int(expires_in),
        bool(token.get("refresh_token")),
        "refresh_expires_in" in token,
    )
    return token
