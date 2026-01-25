"""Custom exceptions for PrivaseeAI.Security."""


class PrivaseeAIError(Exception):
    """Base exception for all PrivaseeAI.Security errors."""

    pass


class ConfigurationError(PrivaseeAIError):
    """Raised when there is a configuration error."""

    pass


class DatabaseError(PrivaseeAIError):
    """Raised when there is a database error."""

    pass


class BackupParseError(PrivaseeAIError):
    """Raised when there is an error parsing iOS backup files."""

    pass


class DeviceNotFoundError(PrivaseeAIError):
    """Raised when a device cannot be found."""

    pass


class EncryptionError(PrivaseeAIError):
    """Raised when there is an encryption/decryption error."""

    pass


class MonitoringError(PrivaseeAIError):
    """Raised when there is an error in the monitoring system."""

    pass


class ValidationError(PrivaseeAIError):
    """Raised when validation fails."""

    pass
