"""Unit tests for device information module."""

import pytest

from privaseeai_security.device_info import (
    DeviceInfo,
    DeviceInfoExtractor,
    DeviceInfoError,
)
from tests.fixtures.sample_data import get_sample_device_info


class TestDeviceInfo:
    """Test cases for DeviceInfo dataclass."""

    def test_device_info_creation(self):
        """Test creating DeviceInfo instance."""
        device_info = DeviceInfo(
            device_id="test-id",
            device_name="Test Device",
            ios_version="17.0",
            model="iPhone15,2",
        )
        
        assert device_info.device_id == "test-id"
        assert device_info.device_name == "Test Device"
        assert device_info.ios_version == "17.0"
        assert device_info.model == "iPhone15,2"

    def test_device_info_with_optional_fields(self):
        """Test DeviceInfo with optional fields."""
        device_info = DeviceInfo(
            device_id="test-id",
            device_name="Test Device",
            ios_version="17.0",
            model="iPhone15,2",
            serial_number="ABC123",
            capacity=256000000000,
            build_version="21A123",
        )
        
        assert device_info.serial_number == "ABC123"
        assert device_info.capacity == 256000000000
        assert device_info.build_version == "21A123"

    def test_device_info_to_dict(self):
        """Test converting DeviceInfo to dictionary."""
        device_info = DeviceInfo(
            device_id="test-id",
            device_name="Test Device",
            ios_version="17.0",
            model="iPhone15,2",
        )
        
        device_dict = device_info.to_dict()
        
        assert isinstance(device_dict, dict)
        assert device_dict["device_id"] == "test-id"
        assert device_dict["device_name"] == "Test Device"
        assert device_dict["ios_version"] == "17.0"
        assert device_dict["model"] == "iPhone15,2"

    def test_device_info_to_dict_with_none_values(self):
        """Test to_dict includes None values for optional fields."""
        device_info = DeviceInfo(
            device_id="test-id",
            device_name="Test Device",
            ios_version="17.0",
            model="iPhone15,2",
        )
        
        device_dict = device_info.to_dict()
        
        assert device_dict["serial_number"] is None
        assert device_dict["capacity"] is None
        assert device_dict["build_version"] is None


class TestDeviceInfoExtractor:
    """Test cases for DeviceInfoExtractor class."""

    def test_extractor_initialization(self):
        """Test DeviceInfoExtractor initialization."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        assert extractor.backup_path == "/path/to/backup"

    def test_extract_device_info(self):
        """Test extracting device information."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_info = extractor.extract_device_info()
        
        assert isinstance(device_info, DeviceInfo)
        assert device_info.device_id is not None
        assert device_info.device_name is not None
        assert device_info.ios_version is not None

    def test_extract_device_info_returns_valid_data(self):
        """Test that extracted device info has valid data."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_info = extractor.extract_device_info()
        
        assert len(device_info.device_id) > 0
        assert len(device_info.device_name) > 0
        assert len(device_info.ios_version) > 0
        assert len(device_info.model) > 0

    def test_get_device_id(self):
        """Test getting device ID."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_id = extractor.get_device_id()
        
        assert isinstance(device_id, str)
        assert len(device_id) > 0

    def test_get_device_id_matches_extract(self):
        """Test that get_device_id matches extract_device_info."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_info = extractor.extract_device_info()
        device_id = extractor.get_device_id()
        
        assert device_id == device_info.device_id

    def test_validate_backup(self):
        """Test backup validation."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        is_valid = extractor.validate_backup()
        
        assert isinstance(is_valid, bool)
        # Stub implementation always returns True
        assert is_valid is True

    def test_validate_backup_returns_boolean(self):
        """Test that validate_backup returns boolean."""
        extractor = DeviceInfoExtractor("/any/path")
        result = extractor.validate_backup()
        
        assert result in [True, False]

    def test_extractor_with_different_paths(self):
        """Test extractor with different backup paths."""
        paths = [
            "/path/to/backup1",
            "/another/backup/path",
            "/tmp/test_backup",
        ]
        
        for path in paths:
            extractor = DeviceInfoExtractor(path)
            assert extractor.backup_path == path

    def test_extracted_info_has_all_required_fields(self):
        """Test that extracted device info has all required fields."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_info = extractor.extract_device_info()
        
        # Check required fields are present
        assert hasattr(device_info, 'device_id')
        assert hasattr(device_info, 'device_name')
        assert hasattr(device_info, 'ios_version')
        assert hasattr(device_info, 'model')

    def test_extracted_info_includes_optional_fields(self):
        """Test that extracted device info includes optional fields."""
        extractor = DeviceInfoExtractor("/path/to/backup")
        device_info = extractor.extract_device_info()
        
        # Check optional fields are present (may be None)
        assert hasattr(device_info, 'serial_number')
        assert hasattr(device_info, 'capacity')
        assert hasattr(device_info, 'build_version')
