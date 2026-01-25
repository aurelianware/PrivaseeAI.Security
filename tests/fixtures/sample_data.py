"""Sample data and fixtures for testing."""

from typing import Dict, Any


# Mock configuration data
MOCK_CONFIG_DATA = {
    "log_level": "DEBUG",
    "log_format": "json",
    "backup_directory": "/tmp/test_backups",
    "encryption_enabled": True,
    "encryption_algorithm": "AES-256-GCM",
    "watch_interval": 1,
    "max_file_size": 52428800,  # 50 MB
}

# Sample iOS backup manifest data (simplified)
SAMPLE_IOS_MANIFEST = {
    "Applications": {
        "com.apple.mobilesafari": {
            "CFBundleIdentifier": "com.apple.mobilesafari",
            "CFBundleDisplayName": "Safari",
            "Path": "/var/mobile/Containers/Bundle/Application/test-uuid",
        },
        "com.apple.mobilemail": {
            "CFBundleIdentifier": "com.apple.mobilemail",
            "CFBundleDisplayName": "Mail",
            "Path": "/var/mobile/Containers/Bundle/Application/test-uuid2",
        },
    },
    "Date": "2026-01-25T12:00:00Z",
    "IsEncrypted": False,
    "Version": "13.0",
    "WasPasscodeSet": True,
}

# Sample device information
SAMPLE_DEVICE_INFO = {
    "device_id": "00008030-001C0123456789AB",
    "device_name": "Test User's iPhone",
    "ios_version": "17.2",
    "model": "iPhone15,2",
    "model_name": "iPhone 14 Pro",
    "serial_number": "F17AB1CD2EF3",
    "capacity": 256000000000,  # 256 GB
    "build_version": "21C62",
    "product_type": "iPhone15,2",
    "unique_device_id": "00008030-001C0123456789AB",
}

# Sample device information #2 (different device)
SAMPLE_DEVICE_INFO_2 = {
    "device_id": "00008110-000D9876543210BA",
    "device_name": "Test iPhone Pro Max",
    "ios_version": "17.3",
    "model": "iPhone15,3",
    "model_name": "iPhone 14 Pro Max",
    "serial_number": "G28BC2DE3FG4",
    "capacity": 512000000000,  # 512 GB
    "build_version": "21D50",
    "product_type": "iPhone15,3",
    "unique_device_id": "00008110-000D9876543210BA",
}

# Sample threat signatures for testing
SAMPLE_THREAT_SIGNATURES = [
    {
        "id": "THREAT-001",
        "name": "Pegasus Spyware Indicator",
        "description": "Known Pegasus spyware file pattern",
        "severity": "CRITICAL",
        "indicators": [
            "com.apple.private.security.storage",
            "kernel.task_dyld_info",
        ],
    },
    {
        "id": "THREAT-002",
        "name": "Suspicious Network Connection",
        "description": "Unexpected network connection pattern",
        "severity": "HIGH",
        "indicators": [
            "tcp://suspicious-domain.com:443",
            "udp://unknown-server.net:53",
        ],
    },
]

# Sample backup file list
SAMPLE_BACKUP_FILES = [
    {
        "path": "Library/AddressBook/AddressBook.sqlitedb",
        "hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        "size": 1024000,
        "modified": "2026-01-25T10:30:00Z",
    },
    {
        "path": "Library/SMS/sms.db",
        "hash": "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
        "size": 2048000,
        "modified": "2026-01-25T11:45:00Z",
    },
    {
        "path": "Library/CallHistoryDB/CallHistory.storedata",
        "hash": "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
        "size": 512000,
        "modified": "2026-01-25T12:15:00Z",
    },
]


def get_mock_config() -> Dict[str, Any]:
    """Get mock configuration data.
    
    Returns:
        Mock configuration dictionary
    """
    return MOCK_CONFIG_DATA.copy()


def get_sample_device_info(device_num: int = 1) -> Dict[str, Any]:
    """Get sample device information.
    
    Args:
        device_num: Device number (1 or 2)
        
    Returns:
        Sample device info dictionary
    """
    if device_num == 2:
        return SAMPLE_DEVICE_INFO_2.copy()
    return SAMPLE_DEVICE_INFO.copy()


def get_sample_manifest() -> Dict[str, Any]:
    """Get sample iOS backup manifest.
    
    Returns:
        Sample manifest dictionary
    """
    return SAMPLE_IOS_MANIFEST.copy()


def get_sample_threat_signatures() -> list:
    """Get sample threat signatures.
    
    Returns:
        List of sample threat signature dictionaries
    """
    return [sig.copy() for sig in SAMPLE_THREAT_SIGNATURES]


def get_sample_backup_files() -> list:
    """Get sample backup file list.
    
    Returns:
        List of sample backup file dictionaries
    """
    return [file.copy() for file in SAMPLE_BACKUP_FILES]
