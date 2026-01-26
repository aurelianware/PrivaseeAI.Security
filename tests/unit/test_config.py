"""Unit tests for configuration module."""

import pytest
from pathlib import Path
import tempfile

from privaseeai_security.config import Config, ConfigError


class TestConfig:
    """Test cases for Config class."""

    def test_init_with_defaults(self):
        """Test configuration initialization with default values."""
        config = Config()
        assert config.get("log_level") == "INFO"
        assert config.get("encryption_enabled") is True
        assert config.get("watch_interval") == 5

    def test_init_with_nonexistent_file(self):
        """Test initialization with non-existent config file."""
        with pytest.raises(ConfigError, match="Configuration file not found"):
            Config(config_path="/nonexistent/config.yaml")

    def test_init_with_existing_file(self):
        """Test initialization with existing config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("test: value")
            temp_path = f.name
        
        try:
            config = Config(config_path=temp_path)
            assert config.config_path == temp_path
        finally:
            Path(temp_path).unlink()

    def test_get_existing_key(self):
        """Test getting existing configuration key."""
        config = Config()
        assert config.get("log_level") == "INFO"

    def test_get_nonexistent_key_with_default(self):
        """Test getting non-existent key with default value."""
        config = Config()
        assert config.get("nonexistent_key", "default_value") == "default_value"

    def test_get_nonexistent_key_without_default(self):
        """Test getting non-existent key without default value."""
        config = Config()
        assert config.get("nonexistent_key") is None

    def test_set_configuration_value(self):
        """Test setting configuration value."""
        config = Config()
        config.set("custom_key", "custom_value")
        assert config.get("custom_key") == "custom_value"

    def test_validate_valid_configuration(self):
        """Test validation of valid configuration."""
        config = Config()
        assert config.validate() is True

    def test_validate_missing_required_key(self):
        """Test validation with missing required key."""
        config = Config()
        # Remove a required key
        config._config.pop("log_level")
        with pytest.raises(ConfigError, match="Missing required configuration: log_level"):
            config.validate()

    def test_validate_invalid_log_level(self):
        """Test validation with invalid log level."""
        config = Config()
        config.set("log_level", "INVALID")
        with pytest.raises(ConfigError, match="Invalid log level"):
            config.validate()

    def test_to_dict(self):
        """Test converting configuration to dictionary."""
        config = Config()
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert "log_level" in config_dict
        assert "backup_directory" in config_dict

    def test_to_dict_is_copy(self):
        """Test that to_dict returns a copy, not the original."""
        config = Config()
        config_dict = config.to_dict()
        config_dict["log_level"] = "MODIFIED"
        assert config.get("log_level") != "MODIFIED"

    def test_load_defaults(self):
        """Test that default values are loaded correctly."""
        config = Config()
        assert config.get("encryption_algorithm") == "AES-256-GCM"
        assert config.get("max_file_size") == 104857600

    def test_custom_backup_directory(self):
        """Test setting custom backup directory."""
        config = Config()
        custom_dir = "/custom/backup/path"
        config.set("backup_directory", custom_dir)
        assert config.get("backup_directory") == custom_dir
