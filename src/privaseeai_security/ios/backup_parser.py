"""iOS backup file parsing utilities."""

import plistlib
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from privaseeai_security.core.exceptions import BackupParseError
from privaseeai_security.core.logger import get_logger

logger = get_logger(__name__)


class BackupParser:
    """Parser for iOS backup files."""

    def __init__(self, backup_path: Path):
        """Initialize backup parser.

        Args:
            backup_path: Path to iOS backup directory
        """
        self.backup_path = backup_path
        self.manifest_db_path = backup_path / "Manifest.db"
        self.manifest_plist_path = backup_path / "Manifest.plist"
        self.info_plist_path = backup_path / "Info.plist"

    def parse_manifest_plist(self) -> Dict[str, Any]:
        """Parse Manifest.plist file.

        Returns:
            Dictionary containing manifest data

        Raises:
            BackupParseError: If parsing fails
        """
        if not self.manifest_plist_path.exists():
            raise BackupParseError(f"Manifest.plist not found: {self.manifest_plist_path}")

        try:
            with open(self.manifest_plist_path, "rb") as f:
                manifest = plistlib.load(f)
            logger.debug(f"Parsed Manifest.plist from {self.backup_path}")
            return manifest
        except Exception as e:
            raise BackupParseError(f"Failed to parse Manifest.plist: {e}") from e

    def parse_info_plist(self) -> Dict[str, Any]:
        """Parse Info.plist file.

        Returns:
            Dictionary containing device info

        Raises:
            BackupParseError: If parsing fails
        """
        if not self.info_plist_path.exists():
            raise BackupParseError(f"Info.plist not found: {self.info_plist_path}")

        try:
            with open(self.info_plist_path, "rb") as f:
                info = plistlib.load(f)
            logger.debug(f"Parsed Info.plist from {self.backup_path}")
            return info
        except Exception as e:
            raise BackupParseError(f"Failed to parse Info.plist: {e}") from e

    def get_manifest_files(self) -> List[Dict[str, Any]]:
        """Get list of files from Manifest.db.

        Returns:
            List of file records from the manifest

        Raises:
            BackupParseError: If database query fails
        """
        if not self.manifest_db_path.exists():
            raise BackupParseError(f"Manifest.db not found: {self.manifest_db_path}")

        try:
            conn = sqlite3.connect(self.manifest_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Query files from manifest
            cursor.execute(
                """
                SELECT fileID, domain, relativePath, flags, file
                FROM Files
                ORDER BY domain, relativePath
                """
            )

            files = []
            for row in cursor:
                files.append(
                    {
                        "file_id": row["fileID"],
                        "domain": row["domain"],
                        "relative_path": row["relativePath"],
                        "flags": row["flags"],
                        "file_blob": row["file"],
                    }
                )

            conn.close()
            logger.debug(f"Found {len(files)} files in Manifest.db")
            return files

        except sqlite3.Error as e:
            raise BackupParseError(f"Failed to query Manifest.db: {e}") from e

    def find_files_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Find files belonging to a specific domain.

        Args:
            domain: Domain to search for (e.g., 'AppDomain-com.apple.MobileSMS')

        Returns:
            List of file records matching the domain

        Raises:
            BackupParseError: If database query fails
        """
        if not self.manifest_db_path.exists():
            raise BackupParseError(f"Manifest.db not found: {self.manifest_db_path}")

        try:
            conn = sqlite3.connect(self.manifest_db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT fileID, domain, relativePath, flags
                FROM Files
                WHERE domain = ?
                ORDER BY relativePath
                """,
                (domain,),
            )

            files = []
            for row in cursor:
                files.append(
                    {
                        "file_id": row["fileID"],
                        "domain": row["domain"],
                        "relative_path": row["relativePath"],
                        "flags": row["flags"],
                    }
                )

            conn.close()
            logger.debug(f"Found {len(files)} files in domain '{domain}'")
            return files

        except sqlite3.Error as e:
            raise BackupParseError(f"Failed to query files by domain: {e}") from e

    def get_installed_apps(self) -> List[str]:
        """Get list of installed applications.

        Returns:
            List of application bundle IDs

        Raises:
            BackupParseError: If query fails
        """
        if not self.manifest_db_path.exists():
            raise BackupParseError(f"Manifest.db not found: {self.manifest_db_path}")

        try:
            conn = sqlite3.connect(self.manifest_db_path)
            cursor = conn.cursor()

            # Extract app domains
            cursor.execute(
                """
                SELECT DISTINCT domain
                FROM Files
                WHERE domain LIKE 'AppDomain-%'
                """
            )

            apps = []
            for row in cursor:
                domain = row[0]
                # Extract bundle ID from domain (format: AppDomain-com.company.app)
                if domain.startswith("AppDomain-"):
                    bundle_id = domain.replace("AppDomain-", "")
                    apps.append(bundle_id)

            conn.close()
            logger.debug(f"Found {len(apps)} installed applications")
            return sorted(apps)

        except sqlite3.Error as e:
            raise BackupParseError(f"Failed to get installed apps: {e}") from e

    def is_encrypted(self) -> bool:
        """Check if backup is encrypted.

        Returns:
            True if backup is encrypted, False otherwise
        """
        try:
            manifest = self.parse_manifest_plist()
            is_encrypted = manifest.get("IsEncrypted", False)
            logger.debug(f"Backup encryption status: {is_encrypted}")
            return is_encrypted
        except BackupParseError:
            # If we can't read the manifest, assume not encrypted
            return False
