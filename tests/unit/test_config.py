"""Unit tests for configuration management."""

import os
from pathlib import Path

import pytest

from privaseeai_security.core.config import (
    DatabaseSettings,
    Environment,
    IOSBackupSettings,
    LogFormat,
    LoggingSettings,
    RedisSettings,
    Settings,
)


def test_database_settings_defaults():
    """Test database settings with defaults."""
    db = DatabaseSettings()
    assert db.host == "localhost"
    assert db.port == 5432
    assert db.name == "privaseeai_security"
    assert db.user == "privaseeai"


def test_database_url():
    """Test database URL generation."""
    db = DatabaseSettings(
        host="testhost",
        port=5433,
        name="testdb",
        user="testuser",
        password="testpass",
    )
    assert db.url == "postgresql://testuser:testpass@testhost:5433/testdb"


def test_redis_settings_defaults():
    """Test Redis settings with defaults."""
    redis = RedisSettings()
    assert redis.host == "localhost"
    assert redis.port == 6379
    assert redis.db == 0


def test_redis_url_without_password():
    """Test Redis URL generation without password."""
    redis = RedisSettings(host="testhost", port=6380, db=1)
    assert redis.url == "redis://testhost:6380/1"


def test_redis_url_with_password():
    """Test Redis URL generation with password."""
    redis = RedisSettings(host="testhost", port=6380, db=1, password="testpass")
    assert redis.url == "redis://:testpass@testhost:6380/1"


def test_ios_backup_settings_defaults():
    """Test iOS backup settings with defaults."""
    ios = IOSBackupSettings()
    assert ios.backup_path == Path("/var/lib/privaseeai/backups")
    assert ios.monitor_interval == 60
    assert ios.backup_retention_days == 90


def test_ios_backup_settings_path_conversion():
    """Test iOS backup path conversion from string."""
    ios = IOSBackupSettings(backup_path="/tmp/test")
    assert isinstance(ios.backup_path, Path)
    assert ios.backup_path == Path("/tmp/test")


def test_logging_settings_defaults():
    """Test logging settings with defaults."""
    logging = LoggingSettings()
    assert logging.level == "INFO"
    assert logging.format == LogFormat.JSON
    assert logging.rotation_size == 10485760
    assert logging.backup_count == 10


def test_settings_defaults():
    """Test main settings with defaults."""
    settings = Settings()
    assert settings.app_name == "PrivaseeAI.Security"
    assert settings.app_env == Environment.DEVELOPMENT
    assert settings.debug is False
    assert settings.max_workers == 4
    assert settings.task_queue_size == 1000
    assert settings.cache_ttl == 3600


def test_settings_with_env_vars(monkeypatch, tmp_path):
    """Test settings loading from environment variables."""
    monkeypatch.setenv("APP_NAME", "TestApp")
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("DATABASE_HOST", "dbhost")
    monkeypatch.setenv("DATABASE_PORT", "5433")
    monkeypatch.setenv("REDIS_HOST", "redishost")
    monkeypatch.setenv("IOS_BACKUP_PATH", str(tmp_path))

    settings = Settings()
    assert settings.app_name == "TestApp"
    assert settings.app_env == Environment.PRODUCTION
    assert settings.debug is True
    assert settings.database.host == "dbhost"
    assert settings.database.port == 5433
    assert settings.redis.host == "redishost"
    assert settings.ios_backup.backup_path == tmp_path
