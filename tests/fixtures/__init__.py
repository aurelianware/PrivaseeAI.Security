"""Test fixtures."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_backup_dir(temp_dir: Path) -> Path:
    """Create a sample iOS backup directory structure."""
    backup_dir = temp_dir / "sample_backup"
    backup_dir.mkdir()

    # Create Info.plist
    info_plist_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Device Name</key>
    <string>Test iPhone</string>
    <key>Product Type</key>
    <string>iPhone14,2</string>
    <key>Product Version</key>
    <string>16.4.1</string>
    <key>Serial Number</key>
    <string>TESTSERIAL123</string>
    <key>Unique Identifier</key>
    <string>test-udid-12345</string>
    <key>Build Version</key>
    <string>20D67</string>
    <key>Last Backup Date</key>
    <date>2024-01-01T12:00:00Z</date>
</dict>
</plist>"""

    (backup_dir / "Info.plist").write_bytes(info_plist_content)

    # Create Manifest.plist
    manifest_plist_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>IsEncrypted</key>
    <false/>
    <key>Version</key>
    <string>3.3</string>
</dict>
</plist>"""

    (backup_dir / "Manifest.plist").write_bytes(manifest_plist_content)

    return backup_dir


@pytest.fixture
def env_file(temp_dir: Path) -> Path:
    """Create a test environment file."""
    env_file = temp_dir / ".env.test"
    env_content = """
APP_NAME=PrivaseeAI.Security.Test
APP_ENV=development
DEBUG=true
LOG_LEVEL=DEBUG

DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=test_db
DATABASE_USER=test_user
DATABASE_PASSWORD=test_pass

REDIS_HOST=localhost
REDIS_PORT=6379

IOS_BACKUP_PATH=/tmp/test/backups
MONITORING_ENABLED=true
"""
    env_file.write_text(env_content)
    return env_file
