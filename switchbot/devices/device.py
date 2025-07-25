"""Library to handle connection with Switchbot."""

from __future__ import annotations

import asyncio
import binascii
import logging
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any, TypeVar, cast
from uuid import UUID

import aiohttp
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTCharacteristic, BleakGATTServiceCollection
from bleak.exc import BleakDBusError
from bleak_retry_connector import (
    BLEAK_RETRY_EXCEPTIONS,
    BleakClientWithServiceCache,
    BleakNotFoundError,
    ble_device_has_changed,
    establish_connection,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..api_config import SWITCHBOT_APP_API_BASE_URL, SWITCHBOT_APP_CLIENT_ID
from ..const import (
    DEFAULT_RETRY_COUNT,
    DEFAULT_SCAN_TIMEOUT,
    ColorMode,  # noqa: F401
    SwitchbotAccountConnectionError,
    SwitchbotApiError,
    SwitchbotAuthenticationError,
    SwitchbotModel,
)
from ..discovery import GetSwitchbotDevices
from ..helpers import create_background_task
from ..models import SwitchBotAdvertisement

_LOGGER = logging.getLogger(__name__)

REQ_HEADER = "570f"


# Keys common to all device types
DEVICE_GET_BASIC_SETTINGS_KEY = "5702"
DEVICE_SET_MODE_KEY = "5703"
DEVICE_SET_EXTENDED_KEY = REQ_HEADER
COMMAND_GET_CK_IV = f"{REQ_HEADER}2103"

# Base key when encryption is set
KEY_PASSWORD_PREFIX = "571"

DBUS_ERROR_BACKOFF_TIME = 0.25

# How long to hold the connection
# to wait for additional commands for
# disconnecting the device.
DISCONNECT_DELAY = 8.5


# If the scanner is in passive mode, we
# need to poll the device to get the
# battery and a few rarely updating
# values.
PASSIVE_POLL_INTERVAL = 60 * 60 * 24


class CharacteristicMissingError(Exception):
    """Raised when a characteristic is missing."""


class SwitchbotOperationError(Exception):
    """Raised when an operation fails."""


def _sb_uuid(comms_type: str = "service") -> UUID | str:
    """Return Switchbot UUID."""
    _uuid = {"tx": "002", "rx": "003", "service": "d00"}

    if comms_type in _uuid:
        return UUID(f"cba20{_uuid[comms_type]}-224d-11e6-9fb8-0002a5d5c51b")

    return "Incorrect type, choose between: tx, rx or service"


READ_CHAR_UUID = _sb_uuid(comms_type="rx")
WRITE_CHAR_UUID = _sb_uuid(comms_type="tx")


WrapFuncType = TypeVar("WrapFuncType", bound=Callable[..., Any])


def update_after_operation(func: WrapFuncType) -> WrapFuncType:
    """Define a wrapper to update after an operation."""

    async def _async_update_after_operation_wrap(
        self: SwitchbotBaseDevice, *args: Any, **kwargs: Any
    ) -> None:
        ret = await func(self, *args, **kwargs)
        await self.update()
        return ret

    return cast(WrapFuncType, _async_update_after_operation_wrap)


def _merge_data(old_data: dict[str, Any], new_data: dict[str, Any]) -> dict[str, Any]:
    """Merge data but only add None keys if they are missing."""
    merged = old_data.copy()
    for key, value in new_data.items():
        if isinstance(value, dict) and isinstance(old_data.get(key), dict):
            merged[key] = _merge_data(old_data[key], value)
        elif value is not None or key not in old_data:
            merged[key] = value
    return merged


def _handle_timeout(fut: asyncio.Future[None]) -> None:
    """Handle a timeout."""
    if not fut.done():
        fut.set_exception(asyncio.TimeoutError)


class SwitchbotBaseDevice:
    """Base Representation of a Switchbot Device."""

    _turn_on_command: str | None = None
    _turn_off_command: str | None = None
    _press_command: str | None = None

    def __init__(
        self,
        device: BLEDevice,
        password: str | None = None,
        interface: int = 0,
        **kwargs: Any,
    ) -> None:
        """Switchbot base class constructor."""
        self._interface = f"hci{interface}"
        self._device = device
        self._sb_adv_data: SwitchBotAdvertisement | None = None
        self._override_adv_data: dict[str, Any] | None = None
        self._scan_timeout: int = kwargs.pop("scan_timeout", DEFAULT_SCAN_TIMEOUT)
        self._retry_count: int = kwargs.pop("retry_count", DEFAULT_RETRY_COUNT)
        self._connect_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()
        if password is None or password == "":
            self._password_encoded = None
        else:
            self._password_encoded = "%08x" % (
                binascii.crc32(password.encode("ascii")) & 0xFFFFFFFF
            )
        self._client: BleakClientWithServiceCache | None = None
        self._read_char: BleakGATTCharacteristic | None = None
        self._write_char: BleakGATTCharacteristic | None = None
        self._disconnect_timer: asyncio.TimerHandle | None = None
        self._expected_disconnect = False
        self.loop = asyncio.get_event_loop()
        self._callbacks: list[Callable[[], None]] = []
        self._notify_future: asyncio.Future[bytearray] | None = None
        self._last_full_update: float = -PASSIVE_POLL_INTERVAL
        self._timed_disconnect_task: asyncio.Task[None] | None = None

    @classmethod
    async def api_request(
        cls,
        session: aiohttp.ClientSession,
        subdomain: str,
        path: str,
        data: dict | None = None,
        headers: dict | None = None,
    ) -> dict:
        url = f"https://{subdomain}.{SWITCHBOT_APP_API_BASE_URL}/{path}"
        async with session.post(
            url,
            json=data,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as result:
            if result.status > 299:
                raise SwitchbotApiError(
                    f"Unexpected status code returned by SwitchBot API: {result.status}"
                )

            response = await result.json()
            if response["statusCode"] != 100:
                raise SwitchbotApiError(
                    f"{response['message']}, status code: {response['statusCode']}"
                )

            return response["body"]

    def advertisement_changed(self, advertisement: SwitchBotAdvertisement) -> bool:
        """Check if the advertisement has changed."""
        return bool(
            not self._sb_adv_data
            or ble_device_has_changed(self._sb_adv_data.device, advertisement.device)
            or advertisement.data != self._sb_adv_data.data
        )

    def _commandkey(self, key: str) -> str:
        """Add password to key if set."""
        if self._password_encoded is None:
            return key
        key_action = key[3]
        key_suffix = key[4:]
        return KEY_PASSWORD_PREFIX + key_action + self._password_encoded + key_suffix

    async def _send_command_locked_with_retry(
        self, key: str, command: bytes, retry: int, max_attempts: int
    ) -> bytes | None:
        for attempt in range(max_attempts):
            try:
                return await self._send_command_locked(key, command)
            except BleakNotFoundError:
                _LOGGER.error(
                    "%s: device not found, no longer in range, or poor RSSI: %s",
                    self.name,
                    self.rssi,
                    exc_info=True,
                )
                raise
            except CharacteristicMissingError as ex:
                if attempt == retry:
                    _LOGGER.error(
                        "%s: characteristic missing: %s; Stopping trying; RSSI: %s",
                        self.name,
                        ex,
                        self.rssi,
                        exc_info=True,
                    )
                    raise

                _LOGGER.debug(
                    "%s: characteristic missing: %s; RSSI: %s",
                    self.name,
                    ex,
                    self.rssi,
                    exc_info=True,
                )
            except BLEAK_RETRY_EXCEPTIONS:
                if attempt == retry:
                    _LOGGER.error(
                        "%s: communication failed; Stopping trying; RSSI: %s",
                        self.name,
                        self.rssi,
                        exc_info=True,
                    )
                    raise

                _LOGGER.debug(
                    "%s: communication failed with:", self.name, exc_info=True
                )

        raise RuntimeError("Unreachable")

    async def _send_command(self, key: str, retry: int | None = None) -> bytes | None:
        """Send command to device and read response."""
        if retry is None:
            retry = self._retry_count
        command = bytearray.fromhex(self._commandkey(key))
        _LOGGER.debug("%s: Scheduling command %s", self.name, command.hex())
        max_attempts = retry + 1
        if self._operation_lock.locked():
            _LOGGER.debug(
                "%s: Operation already in progress, waiting for it to complete; RSSI: %s",
                self.name,
                self.rssi,
            )
        async with self._operation_lock:
            return await self._send_command_locked_with_retry(
                key, command, retry, max_attempts
            )

    @property
    def name(self) -> str:
        """Return device name."""
        return f"{self._device.name} ({self._device.address})"

    @property
    def data(self) -> dict[str, Any]:
        """Return device data."""
        if self._sb_adv_data:
            return self._sb_adv_data.data
        return {}

    @property
    def parsed_data(self) -> dict[str, Any]:
        """Return parsed device data."""
        return self.data.get("data") or {}

    @property
    def rssi(self) -> int:
        """Return RSSI of device."""
        if self._sb_adv_data:
            return self._sb_adv_data.rssi
        return -127

    async def _ensure_connected(self):
        """Ensure connection to device is established."""
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress, waiting for it to complete; RSSI: %s",
                self.name,
                self.rssi,
            )
        if self._client and self._client.is_connected:
            _LOGGER.debug(
                "%s: Already connected before obtaining lock, resetting timer; RSSI: %s",
                self.name,
                self.rssi,
            )
            self._reset_disconnect_timer()
            return
        async with self._connect_lock:
            # Check again while holding the lock
            if self._client and self._client.is_connected:
                _LOGGER.debug(
                    "%s: Already connected after obtaining lock, resetting timer; RSSI: %s",
                    self.name,
                    self.rssi,
                )
                self._reset_disconnect_timer()
                return
            _LOGGER.debug("%s: Connecting; RSSI: %s", self.name, self.rssi)
            client: BleakClientWithServiceCache = await establish_connection(
                BleakClientWithServiceCache,
                self._device,
                self.name,
                self._disconnected,
                use_services_cache=True,
                ble_device_callback=lambda: self._device,
            )
            _LOGGER.debug("%s: Connected; RSSI: %s", self.name, self.rssi)
            self._client = client

            try:
                self._resolve_characteristics(client.services)
            except CharacteristicMissingError as ex:
                _LOGGER.debug(
                    "%s: characteristic missing, clearing cache: %s; RSSI: %s",
                    self.name,
                    ex,
                    self.rssi,
                    exc_info=True,
                )
                await client.clear_cache()
                self._cancel_disconnect_timer()
                await self._execute_disconnect_with_lock()
                raise

            _LOGGER.debug(
                "%s: Starting notify and disconnect timer; RSSI: %s",
                self.name,
                self.rssi,
            )
            self._reset_disconnect_timer()
            await self._start_notify()

    def _resolve_characteristics(self, services: BleakGATTServiceCollection) -> None:
        """Resolve characteristics."""
        self._read_char = services.get_characteristic(READ_CHAR_UUID)
        if not self._read_char:
            raise CharacteristicMissingError(READ_CHAR_UUID)
        self._write_char = services.get_characteristic(WRITE_CHAR_UUID)
        if not self._write_char:
            raise CharacteristicMissingError(WRITE_CHAR_UUID)

    def _reset_disconnect_timer(self):
        """Reset disconnect timer."""
        self._cancel_disconnect_timer()
        self._expected_disconnect = False
        self._disconnect_timer = self.loop.call_later(
            DISCONNECT_DELAY, self._disconnect_from_timer
        )

    def _disconnected(self, client: BleakClientWithServiceCache) -> None:
        """Disconnected callback."""
        if self._expected_disconnect:
            _LOGGER.debug(
                "%s: Disconnected from device; RSSI: %s", self.name, self.rssi
            )
            return
        _LOGGER.warning(
            "%s: Device unexpectedly disconnected; RSSI: %s",
            self.name,
            self.rssi,
        )
        self._cancel_disconnect_timer()

    def _disconnect_from_timer(self):
        """Disconnect from device."""
        if self._operation_lock.locked() and self._client.is_connected:
            _LOGGER.debug(
                "%s: Operation in progress, resetting disconnect timer; RSSI: %s",
                self.name,
                self.rssi,
            )
            self._reset_disconnect_timer()
            return
        self._cancel_disconnect_timer()
        self._timed_disconnect_task = asyncio.create_task(
            self._execute_timed_disconnect()
        )

    def _cancel_disconnect_timer(self):
        """Cancel disconnect timer."""
        if self._disconnect_timer:
            self._disconnect_timer.cancel()
            self._disconnect_timer = None

    async def _execute_forced_disconnect(self) -> None:
        """Execute forced disconnection."""
        self._cancel_disconnect_timer()
        _LOGGER.debug(
            "%s: Executing forced disconnect",
            self.name,
        )
        await self._execute_disconnect()

    async def _execute_timed_disconnect(self) -> None:
        """Execute timed disconnection."""
        _LOGGER.debug(
            "%s: Executing timed disconnect after timeout of %s",
            self.name,
            DISCONNECT_DELAY,
        )
        await self._execute_disconnect()

    async def _execute_disconnect(self) -> None:
        """Execute disconnection."""
        _LOGGER.debug("%s: Executing disconnect", self.name)
        async with self._connect_lock:
            await self._execute_disconnect_with_lock()

    async def _execute_disconnect_with_lock(self) -> None:
        """Execute disconnection while holding the lock."""
        assert self._connect_lock.locked(), "Lock not held"
        _LOGGER.debug("%s: Executing disconnect with lock", self.name)
        if self._disconnect_timer:  # If the timer was reset, don't disconnect
            _LOGGER.debug("%s: Skipping disconnect as timer reset", self.name)
            return
        client = self._client
        self._expected_disconnect = True
        self._client = None
        self._read_char = None
        self._write_char = None
        if not client:
            _LOGGER.debug("%s: Already disconnected", self.name)
            return
        _LOGGER.debug("%s: Disconnecting", self.name)
        try:
            await client.disconnect()
        except BLEAK_RETRY_EXCEPTIONS as ex:
            _LOGGER.warning(
                "%s: Error disconnecting: %s; RSSI: %s",
                self.name,
                ex,
                self.rssi,
            )
        else:
            _LOGGER.debug("%s: Disconnect completed successfully", self.name)

    async def _send_command_locked(self, key: str, command: bytes) -> bytes:
        """Send command to device and read response."""
        await self._ensure_connected()
        try:
            return await self._execute_command_locked(key, command)
        except BleakDBusError as ex:
            # Disconnect so we can reset state and try again
            await asyncio.sleep(DBUS_ERROR_BACKOFF_TIME)
            _LOGGER.debug(
                "%s: RSSI: %s; Backing off %ss; Disconnecting due to error: %s",
                self.name,
                self.rssi,
                DBUS_ERROR_BACKOFF_TIME,
                ex,
            )
            await self._execute_forced_disconnect()
            raise
        except BLEAK_RETRY_EXCEPTIONS as ex:
            # Disconnect so we can reset state and try again
            _LOGGER.debug(
                "%s: RSSI: %s; Disconnecting due to error: %s", self.name, self.rssi, ex
            )
            await self._execute_forced_disconnect()
            raise

    def _notification_handler(self, _sender: int, data: bytearray) -> None:
        """Handle notification responses."""
        if self._notify_future and not self._notify_future.done():
            self._notify_future.set_result(data)
            return
        _LOGGER.debug("%s: Received unsolicited notification: %s", self.name, data)

    async def _start_notify(self) -> None:
        """Start notification."""
        _LOGGER.debug("%s: Subscribe to notifications; RSSI: %s", self.name, self.rssi)
        await self._client.start_notify(self._read_char, self._notification_handler)

    async def _execute_command_locked(self, key: str, command: bytes) -> bytes:
        """Execute command and read response."""
        assert self._client is not None
        assert self._read_char is not None
        assert self._write_char is not None
        self._notify_future = self.loop.create_future()
        client = self._client

        _LOGGER.debug("%s: Sending command: %s", self.name, key)
        await client.write_gatt_char(self._write_char, command, False)

        timeout = 5
        timeout_handle = self.loop.call_at(
            self.loop.time() + timeout, _handle_timeout, self._notify_future
        )
        timeout_expired = False
        try:
            notify_msg = await self._notify_future
        except TimeoutError:
            timeout_expired = True
            raise
        finally:
            if not timeout_expired:
                timeout_handle.cancel()
            self._notify_future = None

        _LOGGER.debug("%s: Notification received: %s", self.name, notify_msg.hex())

        if notify_msg == b"\x07":
            _LOGGER.error("Password required")
        elif notify_msg == b"\t":
            _LOGGER.error("Password incorrect")
        return notify_msg

    def get_address(self) -> str:
        """Return address of device."""
        return self._device.address

    def _override_state(self, state: dict[str, Any]) -> None:
        """Override device state."""
        if self._override_adv_data is None:
            self._override_adv_data = {}
        self._override_adv_data.update(state)
        self._update_parsed_data(state)

    def _get_adv_value(self, key: str, channel: int | None = None) -> Any:
        """Return value from advertisement data."""
        if self._override_adv_data and key in self._override_adv_data:
            _LOGGER.debug(
                "%s: Using override value for %s: %s",
                self.name,
                key,
                self._override_adv_data[key],
            )
            return self._override_adv_data[key]
        if not self._sb_adv_data:
            return None
        if channel is not None:
            return self._sb_adv_data.data["data"].get(channel, {}).get(key)
        return self._sb_adv_data.data["data"].get(key)

    def get_battery_percent(self) -> Any:
        """Return device battery level in percent."""
        return self._get_adv_value("battery")

    def update_from_advertisement(self, advertisement: SwitchBotAdvertisement) -> None:
        """Update device data from advertisement."""
        # Only accept advertisements if the data is not missing
        # if we already have an advertisement with data
        self._device = advertisement.device

    async def get_device_data(
        self, retry: int | None = None, interface: int | None = None
    ) -> SwitchBotAdvertisement | None:
        """Find switchbot devices and their advertisement data."""
        if retry is None:
            retry = self._retry_count

        if interface:
            _interface: int = interface
        else:
            _interface = int(self._interface.replace("hci", ""))

        _data = await GetSwitchbotDevices(interface=_interface).discover(
            retry=retry, scan_timeout=self._scan_timeout
        )

        if self._device.address in _data:
            self._sb_adv_data = _data[self._device.address]

        return self._sb_adv_data

    async def _get_basic_info(
        self, cmd: str = DEVICE_GET_BASIC_SETTINGS_KEY
    ) -> bytes | None:
        """Return basic info of device."""
        _data = await self._send_command(key=cmd, retry=self._retry_count)

        if _data in (b"\x07", b"\x00"):
            _LOGGER.error("Unsuccessful, please try again")
            return None

        return _data

    def _fire_callbacks(self) -> None:
        """Fire callbacks."""
        _LOGGER.debug("%s: Fire callbacks", self.name)
        for callback in self._callbacks:
            callback()

    def subscribe(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Subscribe to device notifications."""
        self._callbacks.append(callback)

        def _unsub() -> None:
            """Unsubscribe from device notifications."""
            self._callbacks.remove(callback)

        return _unsub

    async def update(self, interface: int | None = None) -> None:
        """Update position, battery percent and light level of device."""
        if info := await self.get_basic_info():
            self._last_full_update = time.monotonic()
            self._update_parsed_data(info)
            self._fire_callbacks()

    async def get_basic_info(self) -> dict[str, Any] | None:
        """Get device basic settings."""
        if not (_data := await self._get_basic_info()):
            return None
        return {
            "battery": _data[1],
            "firmware": _data[2] / 10.0,
        }

    def _check_command_result(
        self, result: bytes | None, index: int, values: set[int]
    ) -> bool:
        """Check command result."""
        if not result or len(result) - 1 < index:
            result_hex = result.hex() if result else "None"
            raise SwitchbotOperationError(
                f"{self.name}: Sending command failed (result={result_hex} index={index} expected={values} rssi={self.rssi})"
            )
        return result[index] in values

    def _update_parsed_data(self, new_data: dict[str, Any]) -> bool:
        """
        Update data.

        Returns true if data has changed and False if not.
        """
        if not self._sb_adv_data:
            _LOGGER.exception("No advertisement data to update")
            return None
        old_data = self._sb_adv_data.data.get("data") or {}
        merged_data = _merge_data(old_data, new_data)
        if merged_data == old_data:
            return False
        self._set_parsed_data(self._sb_adv_data, merged_data)
        return True

    def _set_parsed_data(
        self, advertisement: SwitchBotAdvertisement, data: dict[str, Any]
    ) -> None:
        """Set data."""
        self._sb_adv_data = replace(
            advertisement, data=self._sb_adv_data.data | {"data": data}
        )

    def _set_advertisement_data(self, advertisement: SwitchBotAdvertisement) -> None:
        """Set advertisement data."""
        new_data = advertisement.data.get("data") or {}
        if advertisement.active:
            # If we are getting active data, we can assume we are
            # getting active scans and we do not need to poll
            self._last_full_update = time.monotonic()
        if not self._sb_adv_data:
            self._sb_adv_data = advertisement
        elif new_data:
            self._update_parsed_data(new_data)
        self._override_adv_data = None

    def switch_mode(self) -> bool | None:
        """Return true or false from cache."""
        # To get actual position call update() first.
        return self._get_adv_value("switchMode")

    def poll_needed(self, seconds_since_last_poll: float | None) -> bool:
        """Return if device needs polling."""
        if (
            seconds_since_last_poll is not None
            and seconds_since_last_poll < PASSIVE_POLL_INTERVAL
        ):
            return False
        time_since_last_full_update = time.monotonic() - self._last_full_update
        return not time_since_last_full_update < PASSIVE_POLL_INTERVAL

    def _check_function_support(self, cmd: str | None = None) -> None:
        """Check if the command is supported by the device model."""
        if not cmd:
            raise SwitchbotOperationError(
                f"Current device {self._device.address} does not support this functionality"
            )

    @update_after_operation
    async def turn_on(self) -> bool:
        """Turn device on."""
        self._check_function_support(self._turn_on_command)
        result = await self._send_command(self._turn_on_command)
        return self._check_command_result(result, 0, {1})

    @update_after_operation
    async def turn_off(self) -> bool:
        """Turn device off."""
        self._check_function_support(self._turn_off_command)
        result = await self._send_command(self._turn_off_command)
        return self._check_command_result(result, 0, {1})

    @update_after_operation
    async def press(self) -> bool:
        """Press the device."""
        self._check_function_support(self._press_command)
        result = await self._send_command(self._press_command)
        return self._check_command_result(result, 0, {1})


class SwitchbotDevice(SwitchbotBaseDevice):
    """
    Base Representation of a Switchbot Device.

    This base class consumes the advertisement data during connection. If the device
    sends stale advertisement data while connected, use
    SwitchbotDeviceOverrideStateDuringConnection instead.
    """

    def update_from_advertisement(self, advertisement: SwitchBotAdvertisement) -> None:
        """Update device data from advertisement."""
        super().update_from_advertisement(advertisement)
        self._set_advertisement_data(advertisement)


class SwitchbotEncryptedDevice(SwitchbotDevice):
    """A Switchbot device that uses encryption."""

    def __init__(
        self,
        device: BLEDevice,
        key_id: str,
        encryption_key: str,
        model: SwitchbotModel,
        interface: int = 0,
        **kwargs: Any,
    ) -> None:
        """Switchbot base class constructor for encrypted devices."""
        if len(key_id) == 0:
            raise ValueError("key_id is missing")
        if len(key_id) != 2:
            raise ValueError("key_id is invalid")
        if len(encryption_key) == 0:
            raise ValueError("encryption_key is missing")
        if len(encryption_key) != 32:
            raise ValueError("encryption_key is invalid")
        self._key_id = key_id
        self._encryption_key = bytearray.fromhex(encryption_key)
        self._iv: bytes | None = None
        self._cipher: bytes | None = None
        super().__init__(device, None, interface, **kwargs)
        self._model = model

    # Old non-async method preserved for backwards compatibility
    @classmethod
    def retrieve_encryption_key(cls, device_mac: str, username: str, password: str):
        async def async_fn():
            async with aiohttp.ClientSession() as session:
                return await cls.async_retrieve_encryption_key(
                    session, device_mac, username, password
                )

        return asyncio.run(async_fn())

    @classmethod
    async def async_retrieve_encryption_key(
        cls,
        session: aiohttp.ClientSession,
        device_mac: str,
        username: str,
        password: str,
    ) -> dict:
        """Retrieve lock key from internal SwitchBot API."""
        device_mac = device_mac.replace(":", "").replace("-", "").upper()

        try:
            auth_result = await cls.api_request(
                session,
                "account",
                "account/api/v1/user/login",
                {
                    "clientId": SWITCHBOT_APP_CLIENT_ID,
                    "username": username,
                    "password": password,
                    "grantType": "password",
                    "verifyCode": "",
                },
            )
            auth_headers = {"authorization": auth_result["access_token"]}
        except Exception as err:
            raise SwitchbotAuthenticationError(f"Authentication failed: {err}") from err

        try:
            userinfo = await cls.api_request(
                session, "account", "account/api/v1/user/userinfo", {}, auth_headers
            )
            if "botRegion" in userinfo and userinfo["botRegion"] != "":
                region = userinfo["botRegion"]
            else:
                region = "us"
        except Exception as err:
            raise SwitchbotAccountConnectionError(
                f"Failed to retrieve SwitchBot Account user details: {err}"
            ) from err

        try:
            device_info = await cls.api_request(
                session,
                f"wonderlabs.{region}",
                "wonder/keys/v1/communicate",
                {
                    "device_mac": device_mac,
                    "keyType": "user",
                },
                auth_headers,
            )

            return {
                "key_id": device_info["communicationKey"]["keyId"],
                "encryption_key": device_info["communicationKey"]["key"],
            }
        except Exception as err:
            raise SwitchbotAccountConnectionError(
                f"Failed to retrieve encryption key from SwitchBot Account: {err}"
            ) from err

    @classmethod
    async def verify_encryption_key(
        cls,
        device: BLEDevice,
        key_id: str,
        encryption_key: str,
        model: SwitchbotModel,
        **kwargs: Any,
    ) -> bool:
        try:
            switchbot_device = cls(
                device, key_id=key_id, encryption_key=encryption_key, model=model
            )
        except ValueError:
            return False
        try:
            info = await switchbot_device.get_basic_info()
        except SwitchbotOperationError:
            return False

        return info is not None

    async def _send_command(
        self, key: str, retry: int | None = None, encrypt: bool = True
    ) -> bytes | None:
        if not encrypt:
            return await super()._send_command(key[:2] + "000000" + key[2:], retry)

        if retry is None:
            retry = self._retry_count

        if self._operation_lock.locked():
            _LOGGER.debug(
                "%s: Operation already in progress, waiting for it to complete; RSSI: %s",
                self.name,
                self.rssi,
            )

        async with self._operation_lock:
            if not (result := await self._ensure_encryption_initialized()):
                _LOGGER.error("Failed to initialize encryption")
                return None

            encrypted = (
                key[:2] + self._key_id + self._iv[0:2].hex() + self._encrypt(key[2:])
            )
            command = bytearray.fromhex(self._commandkey(encrypted))
            _LOGGER.debug("%s: Scheduling command %s", self.name, command.hex())
            max_attempts = retry + 1

            result = await self._send_command_locked_with_retry(
                encrypted, command, retry, max_attempts
            )
            if result is None:
                return None
            return result[:1] + self._decrypt(result[4:])

    async def _ensure_encryption_initialized(self) -> bool:
        """Ensure encryption is initialized, must be called with operation lock held."""
        assert self._operation_lock.locked(), "Operation lock must be held"

        if self._iv is not None:
            return True

        _LOGGER.debug("%s: Initializing encryption", self.name)
        # Call parent's _send_command_locked_with_retry directly since we already hold the lock
        key = COMMAND_GET_CK_IV + self._key_id
        command = bytearray.fromhex(self._commandkey(key[:2] + "000000" + key[2:]))

        result = await self._send_command_locked_with_retry(
            key[:2] + "000000" + key[2:],
            command,
            self._retry_count,
            self._retry_count + 1,
        )
        if result is None:
            return False

        if ok := self._check_command_result(result, 0, {1}):
            self._iv = result[4:]
            self._cipher = None  # Reset cipher when IV changes
            _LOGGER.debug("%s: Encryption initialized successfully", self.name)

        return ok

    async def _execute_disconnect(self) -> None:
        async with self._connect_lock:
            self._iv = None
            self._cipher = None
            await self._execute_disconnect_with_lock()

    def _get_cipher(self) -> Cipher:
        if self._cipher is None:
            if self._iv is None:
                raise RuntimeError("Cannot create cipher: IV is None")
            self._cipher = Cipher(
                algorithms.AES128(self._encryption_key), modes.CTR(self._iv)
            )
        return self._cipher

    def _encrypt(self, data: str) -> str:
        if len(data) == 0:
            return ""
        if self._iv is None:
            raise RuntimeError("Cannot encrypt: IV is None")
        encryptor = self._get_cipher().encryptor()
        return (encryptor.update(bytearray.fromhex(data)) + encryptor.finalize()).hex()

    def _decrypt(self, data: bytearray) -> bytes:
        if len(data) == 0:
            return b""
        if self._iv is None:
            if self._expected_disconnect:
                _LOGGER.debug(
                    "%s: Cannot decrypt, IV is None during expected disconnect",
                    self.name,
                )
                return b""
            raise RuntimeError("Cannot decrypt: IV is None")
        decryptor = self._get_cipher().decryptor()
        return decryptor.update(data) + decryptor.finalize()


class SwitchbotDeviceOverrideStateDuringConnection(SwitchbotBaseDevice):
    """
    Base Representation of a Switchbot Device.

    This base class ignores the advertisement data during connection and uses the
    data from the device instead.
    """

    def update_from_advertisement(self, advertisement: SwitchBotAdvertisement) -> None:
        super().update_from_advertisement(advertisement)
        if self._client and self._client.is_connected:
            # We do not consume the advertisement data if we are connected
            # to the device. This is because the advertisement data is not
            # updated when the device is connected for some devices.
            _LOGGER.debug("%s: Ignore advertisement data during connection", self.name)
            return
        self._set_advertisement_data(advertisement)


class SwitchbotSequenceDevice(SwitchbotDevice):
    """
    A Switchbot sequence device.

    This class must not use SwitchbotDeviceOverrideStateDuringConnection because
    it needs to know when the sequence_number has changed.
    """

    def update_from_advertisement(self, advertisement: SwitchBotAdvertisement) -> None:
        """Update device data from advertisement."""
        current_state = self._get_adv_value("sequence_number")
        super().update_from_advertisement(advertisement)
        new_state = self._get_adv_value("sequence_number")
        _LOGGER.debug(
            "%s: update advertisement: %s (seq before: %s) (seq after: %s)",
            self.name,
            advertisement,
            current_state,
            new_state,
        )
        if current_state != new_state:
            create_background_task(self.update())
