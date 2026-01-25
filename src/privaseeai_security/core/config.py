"""Configuration management for PrivaseeAI.Security."""

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Application environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogFormat(str, Enum):
    """Log format options."""

    JSON = "json"
    TEXT = "text"


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""

    host: str = Field(default="localhost", description="Database host")
    port: int = Field(default=5432, description="Database port")
    name: str = Field(default="privaseeai_security", description="Database name")
    user: str = Field(default="privaseeai", description="Database user")
    password: str = Field(default="", description="Database password")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max pool overflow")

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    @property
    def url(self) -> str:
        """Get database URL."""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisSettings(BaseSettings):
    """Redis configuration settings."""

    host: str = Field(default="localhost", description="Redis host")
    port: int = Field(default=6379, description="Redis port")
    db: int = Field(default=0, description="Redis database number")
    password: str = Field(default="", description="Redis password")

    model_config = SettingsConfigDict(env_prefix="REDIS_")

    @property
    def url(self) -> str:
        """Get Redis URL."""
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"


class IOSBackupSettings(BaseSettings):
    """iOS backup configuration settings."""

    backup_path: Path = Field(
        default=Path("/var/lib/privaseeai/backups"), description="iOS backup directory path"
    )
    monitor_interval: int = Field(default=60, description="Monitoring interval in seconds")
    backup_retention_days: int = Field(default=90, description="Backup retention period in days")

    model_config = SettingsConfigDict(env_prefix="IOS_")

    @field_validator("backup_path", mode="before")
    @classmethod
    def validate_backup_path(cls, v: str | Path) -> Path:
        """Validate and convert backup path."""
        path = Path(v) if isinstance(v, str) else v
        return path


class SecuritySettings(BaseSettings):
    """Security configuration settings."""

    encryption_key: str = Field(default="", description="Encryption key for data at rest")
    secret_key: str = Field(default="", description="Secret key for sessions")
    jwt_secret_key: str = Field(default="", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expiration_hours: int = Field(default=24, description="JWT expiration in hours")

    model_config = SettingsConfigDict(env_prefix="")


class MonitoringSettings(BaseSettings):
    """Monitoring configuration settings."""

    enabled: bool = Field(default=True, description="Enable monitoring")
    file_watch_debounce_seconds: int = Field(
        default=5, description="File watch debounce time in seconds"
    )
    threat_scan_interval: int = Field(default=300, description="Threat scan interval in seconds")

    model_config = SettingsConfigDict(env_prefix="MONITORING_")


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""

    level: str = Field(default="INFO", description="Log level")
    format: LogFormat = Field(default=LogFormat.JSON, description="Log format")
    file_path: Optional[Path] = Field(
        default=Path("/var/log/privaseeai/security.log"), description="Log file path"
    )
    rotation_size: int = Field(default=10485760, description="Log rotation size in bytes (10 MB)")
    backup_count: int = Field(default=10, description="Number of backup log files")

    model_config = SettingsConfigDict(env_prefix="LOG_")

    @field_validator("file_path", mode="before")
    @classmethod
    def validate_file_path(cls, v: str | Path | None) -> Optional[Path]:
        """Validate and convert log file path."""
        if v is None:
            return None
        return Path(v) if isinstance(v, str) else v


class Settings(BaseSettings):
    """Main application settings."""

    app_name: str = Field(default="PrivaseeAI.Security", description="Application name")
    app_env: Environment = Field(default=Environment.DEVELOPMENT, description="Application environment")
    debug: bool = Field(default=False, description="Debug mode")

    # Sub-settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    ios_backup: IOSBackupSettings = Field(default_factory=IOSBackupSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    # Performance settings
    max_workers: int = Field(default=4, description="Maximum number of worker threads")
    task_queue_size: int = Field(default=1000, description="Task queue size")
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @classmethod
    def load(cls, env_file: Optional[str] = None) -> "Settings":
        """Load settings from environment file."""
        if env_file and os.path.exists(env_file):
            return cls(_env_file=env_file)
        return cls()


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings.load()
    return _settings


def reload_settings(env_file: Optional[str] = None) -> Settings:
    """Reload settings from environment file."""
    global _settings
    _settings = Settings.load(env_file)
    return _settings
