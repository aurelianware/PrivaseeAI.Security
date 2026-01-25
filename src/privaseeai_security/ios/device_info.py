"""Device information extraction from iOS backups."""

import plistlib
from pathlib import Path

from privaseeai_security.core.exceptions import BackupParseError, DeviceNotFoundError
from privaseeai_security.core.logger import get_logger

logger = get_logger(__name__)


class DeviceInfo:
    """iOS device information extracted from backup."""

    def __init__(
        self,
        device_name: str | None = None,
        device_model: str | None = None,
        product_type: str | None = None,
        product_version: str | None = None,
        serial_number: str | None = None,
        unique_identifier: str | None = None,
        build_version: str | None = None,
        last_backup_date: str | None = None,
        phone_number: str | None = None,
        iccid: str | None = None,
        imei: str | None = None,
    ):
        """Initialize device info.

        Args:
            device_name: User-assigned device name
            device_model: Device model (e.g., iPhone14,2)
            product_type: Product type (e.g., iPhone13,4)
            product_version: iOS version (e.g., 16.4.1)
            serial_number: Device serial number
            unique_identifier: Device UDID
            build_version: iOS build version
            last_backup_date: Last backup timestamp
            phone_number: Phone number if available
            iccid: SIM card ICCID
            imei: Device IMEI
        """
        self.device_name = device_name
        self.device_model = device_model
        self.product_type = product_type
        self.product_version = product_version
        self.serial_number = serial_number
        self.unique_identifier = unique_identifier
        self.build_version = build_version
        self.last_backup_date = last_backup_date
        self.phone_number = phone_number
        self.iccid = iccid
        self.imei = imei

    def to_dict(self) -> dict[str, any]:
        """Convert device info to dictionary."""
        return {
            "device_name": self.device_name,
            "device_model": self.device_model,
            "product_type": self.product_type,
            "product_version": self.product_version,
            "serial_number": self.serial_number,
            "unique_identifier": self.unique_identifier,
            "build_version": self.build_version,
            "last_backup_date": self.last_backup_date,
            "phone_number": self.phone_number,
            "iccid": self.iccid,
            "imei": self.imei,
        }

    def __str__(self) -> str:
        """String representation of device info."""
        return (
            f"Device: {self.device_name or 'Unknown'}\n"
            f"Model: {self.device_model or 'Unknown'}\n"
            f"iOS Version: {self.product_version or 'Unknown'}\n"
            f"Serial: {self.serial_number or 'Unknown'}\n"
            f"UDID: {self.unique_identifier or 'Unknown'}"
        )


def extract_device_info(backup_path: Path) -> DeviceInfo:
    """Extract device information from iOS backup.

    Args:
        backup_path: Path to iOS backup directory

    Returns:
        DeviceInfo object with extracted information

    Raises:
        DeviceNotFoundError: If backup path doesn't exist
        BackupParseError: If Info.plist cannot be parsed
    """
    if not backup_path.exists():
        raise DeviceNotFoundError(f"Backup path does not exist: {backup_path}")

    info_plist_path = backup_path / "Info.plist"
    if not info_plist_path.exists():
        raise BackupParseError(f"Info.plist not found in backup: {backup_path}")

    try:
        with open(info_plist_path, "rb") as f:
            info_plist = plistlib.load(f)

        logger.debug(f"Parsing device info from: {info_plist_path}")

        device_info = DeviceInfo(
            device_name=info_plist.get("Device Name"),
            product_type=info_plist.get("Product Type"),
            product_version=info_plist.get("Product Version"),
            serial_number=info_plist.get("Serial Number"),
            unique_identifier=info_plist.get("Unique Identifier"),
            build_version=info_plist.get("Build Version"),
            last_backup_date=(
                str(info_plist.get("Last Backup Date", ""))
                if info_plist.get("Last Backup Date")
                else None
            ),
            phone_number=info_plist.get("Phone Number"),
            iccid=info_plist.get("ICCID"),
            imei=info_plist.get("IMEI"),
        )

        # Try to get device model from manifest if available
        manifest_plist_path = backup_path / "Manifest.plist"
        if manifest_plist_path.exists():
            try:
                with open(manifest_plist_path, "rb") as f:
                    manifest_plist = plistlib.load(f)
                if not device_info.device_model:
                    device_info.device_model = manifest_plist.get("Lockdown", {}).get("DeviceClass")
            except Exception as e:
                logger.debug(f"Could not read Manifest.plist: {e}")

        logger.info(
            f"Extracted device info: {device_info.device_name} ({device_info.product_version})"
        )
        return device_info

    except plistlib.InvalidFileException as e:
        raise BackupParseError(f"Invalid plist file: {e}") from e
    except Exception as e:
        raise BackupParseError(f"Failed to parse device info: {e}") from e


def find_backup_directories(backups_root: Path) -> list[Path]:
    """Find all iOS backup directories in a root directory.

    Args:
        backups_root: Root directory containing iOS backups

    Returns:
        List of paths to backup directories
    """
    if not backups_root.exists():
        logger.warning(f"Backups root directory does not exist: {backups_root}")
        return []

    backup_dirs = []
    for item in backups_root.iterdir():
        if item.is_dir():
            # Check if it looks like a backup directory (has Info.plist)
            info_plist = item / "Info.plist"
            if info_plist.exists():
                backup_dirs.append(item)

    logger.info(f"Found {len(backup_dirs)} backup directories in {backups_root}")
    return backup_dirs
