"""Library to handle connection with Switchbot."""

from __future__ import annotations

import time

from .device import REQ_HEADER, SwitchbotDeviceOverrideStateDuringConnection

# Plug Mini keys
PLUG_ON_KEY = f"{REQ_HEADER}50010180"
PLUG_OFF_KEY = f"{REQ_HEADER}50010100"


class SwitchbotPlugMini(SwitchbotDeviceOverrideStateDuringConnection):
    """Representation of a Switchbot plug mini."""

    async def update(self, interface: int | None = None) -> None:
        """Update state of device."""
        # No battery here
        self._last_full_update = time.monotonic()

    async def turn_on(self) -> bool:
        """Turn device on."""
        result = await self._send_command(PLUG_ON_KEY)
        ret = self._check_command_result(result, 1, {0x80})
        self._override_state({"isOn": True})
        self._fire_callbacks()
        return ret

    async def turn_off(self) -> bool:
        """Turn device off."""
        result = await self._send_command(PLUG_OFF_KEY)
        ret = self._check_command_result(result, 1, {0x80})
        self._override_state({"isOn": False})
        self._fire_callbacks()
        return ret

    def is_on(self) -> bool | None:
        """Return switch state from cache."""
        return self._get_adv_value("isOn")

    def poll_needed(self, last_poll_time: float | None) -> bool:
        """Return if device needs polling."""
        return False
