"""PrivaseeAI Security - iOS Threat Detection & Monitoring System."""

__version__ = "0.3.0"
__author__ = "AurelianWare"
__description__ = "Privacy-preserving iOS threat detection and monitoring system"

from .config import Config
from .logger import setup_logger

__all__ = ["Config", "setup_logger", "__version__"]
