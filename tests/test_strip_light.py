from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bleak.backends.device import BLEDevice

from switchbot import SwitchBotAdvertisement, SwitchbotEncryptedDevice, SwitchbotModel
from switchbot.devices.strip_light_3 import SwitchbotStripLight3

from .test_adv_parser import generate_ble_device

common_params = [
    (b"7\x00\x00\x95-\x00", "7"),
    (b"*\x00\x00\x15\x04\x00", "*"),
    (b"+\x00\x00\x15\x04\x00", "+"),
    (b"8\x00\x00\x95-\x00", "8"),
]


def create_device_for_command_testing(
    rawAdvData: bytes, model: str, init_data: dict | None = None
):
    ble_device = generate_ble_device("aa:bb:cc:dd:ee:ff", "any")
    device = SwitchbotStripLight3(
        ble_device, "ff", "ffffffffffffffffffffffffffffffff"
    )
    device.update_from_advertisement(
        make_advertisement_data(ble_device, rawAdvData, model, init_data)
    )
    device._send_command = AsyncMock()
    device._check_command_result = MagicMock()
    device.update = AsyncMock()
    return device


def make_advertisement_data(
    ble_device: BLEDevice, rawAdvData: bytes, model: str, init_data: dict | None = None
):
    """Set advertisement data with defaults."""
    if init_data is None:
        init_data = {}

    return SwitchBotAdvertisement(
        address="aa:bb:cc:dd:ee:ff",
        data={
            "rawAdvData": rawAdvData,
            "data": {
                "isOn": True,
                "mode": "level_3",
                "isAqiValid": False,
                "child_lock": False,
                "speed": 100,
                "aqi_level": "excellent",
                "filter element working time": 405,
                "err_code": 0,
                "sequence_number": 161,
            }
            | init_data,
            "isEncrypted": False,
            "model": model,
            "modelFriendlyName": "Air Purifier",
            "modelName": SwitchbotModel.AIR_PURIFIER,
        },
        device=ble_device,
        rssi=-80,
        active=True,
    )