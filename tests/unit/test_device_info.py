"""Unit tests for iOS device information extraction."""

from pathlib import Path

import pytest

from privaseeai_security.core.exceptions import BackupParseError, DeviceNotFoundError
from privaseeai_security.ios.device_info import DeviceInfo, extract_device_info


def test_device_info_initialization():
    """Test DeviceInfo initialization."""
    device = DeviceInfo(
        device_name="Test iPhone",
        device_model="iPhone14,2",
        product_type="iPhone13,4",
        product_version="16.4.1",
        serial_number="TESTSERIAL",
        unique_identifier="test-udid",
    )

    assert device.device_name == "Test iPhone"
    assert device.device_model == "iPhone14,2"
    assert device.product_type == "iPhone13,4"
    assert device.product_version == "16.4.1"
    assert device.serial_number == "TESTSERIAL"
    assert device.unique_identifier == "test-udid"


def test_device_info_to_dict():
    """Test DeviceInfo to_dict conversion."""
    device = DeviceInfo(
        device_name="Test iPhone",
        product_version="16.4.1",
    )

    data = device.to_dict()
    assert isinstance(data, dict)
    assert data["device_name"] == "Test iPhone"
    assert data["product_version"] == "16.4.1"


def test_device_info_str():
    """Test DeviceInfo string representation."""
    device = DeviceInfo(
        device_name="Test iPhone",
        device_model="iPhone14,2",
        product_version="16.4.1",
        serial_number="TESTSERIAL",
        unique_identifier="test-udid",
    )

    device_str = str(device)
    assert "Test iPhone" in device_str
    assert "16.4.1" in device_str
    assert "TESTSERIAL" in device_str


def test_extract_device_info_success(sample_backup_dir):
    """Test extracting device info from backup directory."""
    device = extract_device_info(sample_backup_dir)

    assert device.device_name == "Test iPhone"
    assert device.product_type == "iPhone14,2"
    assert device.product_version == "16.4.1"
    assert device.serial_number == "TESTSERIAL123"
    assert device.unique_identifier == "test-udid-12345"
    assert device.build_version == "20D67"


def test_extract_device_info_missing_backup(tmp_path):
    """Test extracting device info from non-existent backup."""
    with pytest.raises(DeviceNotFoundError):
        extract_device_info(tmp_path / "nonexistent")


def test_extract_device_info_missing_info_plist(tmp_path):
    """Test extracting device info when Info.plist is missing."""
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()

    with pytest.raises(BackupParseError):
        extract_device_info(backup_dir)
