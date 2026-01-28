"""Configuration management for PrivaseeAI Security."""

import os
import yaml
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
            # Logging
            "log_level": "INFO",
            "log_format": "json",
            
            # Paths
            "backup_directory": str(Path.home() / "Library" / "Application Support" / "MobileSync" / "Backup"),
            
            # Monitoring
            "monitor_interval": 30,  # seconds
            "scan_on_startup": True,
            "watch_interval": 5,
            
            # Encryption
            "encryption_enabled": True,
            "encryption_algorithm": "AES-256-GCM",
            "max_file_size": 104857600,  # 100 MB
            
            # Alerting
            "telegram_enabled": True,
            "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
            "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
            "alert_throttle_minutes": 15,
            
            # Threat levels to alert on
            "alert_on_levels": ["CRITICAL", "HIGH"],
        }

    def load_from_file(self, config_path: str) -> None:
        """Load configuration from YAML file.
        
        Args:
            config_path: Path to YAML configuration file
            
        Raises:
            ConfigError: If file cannot be loaded or parsed
        """
        path = Path(config_path)
        if not path.exists():
            raise ConfigError(f"Configuration file not found: {config_path}")
        
        try:
            with open(path, 'r') as f:
                file_config = yaml.safe_load(f) or {}
            
            # Merge with defaults (file config takes precedence)
            self._config.update(file_config)
            self.config_path = config_path
            
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigError(f"Error loading configuration file: {e}")

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
    
    def save_to_file(self, config_path: str) -> None:
        """Save current configuration to YAML file.
        
        Args:
            config_path: Path to save configuration
            
        Raises:
            ConfigError: If file cannot be written
        """
        try:
            path = Path(config_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)
            
            self.config_path = config_path
            
        except Exception as e:
            raise ConfigError(f"Error saving configuration file: {e}")
    
    @classmethod
    def get_default_config_path(cls) -> Path:
        """Get default configuration file path.
        
        Returns:
            Path to default config file
        """
        return Path.home() / ".config" / "privaseeai" / "config.yaml"
    
    @classmethod
    def load_or_create_default(cls) -> "Config":
        """Load configuration or create default if none exists.
        
        Returns:
            Config instance
        """
        default_path = cls.get_default_config_path()
        
        if default_path.exists():
            return cls(str(default_path))
        else:
            config = cls()
            # Optionally save default config
            # config.save_to_file(str(default_path))
            return config
