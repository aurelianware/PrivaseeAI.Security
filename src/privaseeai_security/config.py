"""Configuration management for PrivaseeAI Security."""

from pathlib import Path
from typing import Any, Dict, Optional


class ConfigError(Exception):
    """Configuration error exception."""
    pass


class Config:
    """Configuration manager for PrivaseeAI Security."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_path: Path to configuration file (optional)
        """
        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self._load_defaults()
        if config_path:
            self.load_from_file(config_path)

    def _load_defaults(self) -> None:
        """Load default configuration values."""
        self._config = {
            "log_level": "INFO",
            "log_format": "json",
            "backup_directory": str(Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"),
            "encryption_enabled": True,
            "encryption_algorithm": "AES-256-GCM",
            "watch_interval": 5,
            "max_file_size": 104857600,  # 100 MB
        }

    def load_from_file(self, config_path: str) -> None:
        """Load configuration from file.
        
        Args:
            config_path: Path to configuration file
            
        Raises:
            ConfigError: If file cannot be loaded
        """
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        
        # For now, just note that we would parse the file
        # In a real implementation, this would parse JSON/YAML/TOML
        self.config_path = config_path

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        self._config[key] = value

    def validate(self) -> bool:
        """Validate configuration.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigError: If configuration is invalid
        """
        required_keys = ["log_level", "backup_directory"]
        for key in required_keys:
            if key not in self._config:
                raise ConfigError(f"Missing required configuration: {key}")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self._config["log_level"] not in valid_log_levels:
            raise ConfigError(f"Invalid log level: {self._config['log_level']}")
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary.
        
        Returns:
            Configuration dictionary
        """
        return self._config.copy()
