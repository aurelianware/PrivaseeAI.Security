"""Device information extraction for iOS devices."""

from dataclasses import dataclass
from typing import Any, Dict, Optional


class DeviceInfoError(Exception):
    """Device information error exception."""
    pass


@dataclass
class DeviceInfo:
    """iOS device information."""
    
    device_id: str
    device_name: str
    ios_version: str
    model: str
    serial_number: Optional[str] = None
    capacity: Optional[int] = None
    build_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert device info to dictionary.
        
        Returns:
            Dictionary representation of device info
        """
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "ios_version": self.ios_version,
            "model": self.model,
            "serial_number": self.serial_number,
            "capacity": self.capacity,
            "build_version": self.build_version,
        }


class DeviceInfoExtractor:
    """Extract device information from iOS backups."""

    def __init__(self, backup_path: str):
        """Initialize device info extractor.
        
        Args:
            backup_path: Path to iOS backup directory
        """
        self.backup_path = backup_path

    def extract_device_info(self) -> DeviceInfo:
        """Extract device information from backup.
        
        Returns:
            DeviceInfo object
            
        Raises:
            DeviceInfoError: If device info cannot be extracted
            
        Note:
            This is a stub implementation. Real implementation would parse
            Info.plist and Manifest.plist from iOS backup.
        """
        # Stub implementation - return mock data
        return DeviceInfo(
            device_id="test-device-001",
            device_name="Test iPhone",
            ios_version="17.2",
            model="iPhone 15 Pro",
            serial_number="C02YW0ECJHD5",
            capacity=256000000000,
            build_version="21C62",
        )

    def get_device_id(self) -> str:
        """Get device ID from backup.
        
        Returns:
            Device ID string
            
        Raises:
            DeviceInfoError: If device ID cannot be found
        """
        try:
            device_info = self.extract_device_info()
            return device_info.device_id
        except Exception as e:
            raise DeviceInfoError(f"Failed to get device ID: {str(e)}") from e

    def validate_backup(self) -> bool:
        """Validate iOS backup structure.
        
        Returns:
            True if backup is valid, False otherwise
        """
        # Stub implementation - always return True
        return True
