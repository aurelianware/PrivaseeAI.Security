"""Telegram alerting for real-time threat notifications.

This module provides Telegram bot integration for sending security alerts
when threats are detected by the monitoring system.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from enum import Enum

from ..logger import get_logger
from ..crypto.cert_validator import ThreatLevel

# Note: ThreatDetection dataclass is defined in each monitor module
# (vpn_integrity.ThreatDetection, api_abuse.APIThreatDetection)
# This module accepts any threat detection object with the required attributes


class TelegramAlerter:
    """Send security alerts via Telegram bot.
    
    This class handles sending formatted threat alerts to a Telegram chat.
    It includes alert throttling to prevent spam and formats messages with
    severity indicators.
    
    Configuration via environment variables:
    - TELEGRAM_BOT_TOKEN: Telegram bot API token
    - TELEGRAM_CHAT_ID: Target chat ID for alerts
    - ALERT_THROTTLE_MINUTES: Minimum minutes between similar alerts (default: 15)
    
    Example:
        alerter = TelegramAlerter()
        alerter.send_threat_alert(threat_detection)
    """
    
    # Emoji indicators for threat levels
    SEVERITY_EMOJI = {
        ThreatLevel.NONE: "🟢",
        ThreatLevel.LOW: "🟡",
        ThreatLevel.MEDIUM: "🟠",
        ThreatLevel.HIGH: "🔴",
        ThreatLevel.CRITICAL: "🚨"
    }
    
    # Recommended actions by threat level
    RECOMMENDED_ACTIONS = {
        ThreatLevel.NONE: "No action required - monitoring continues",
        ThreatLevel.LOW: "Review logs for additional context",
        ThreatLevel.MEDIUM: "Investigate and monitor for escalation",
        ThreatLevel.HIGH: "Take immediate action - potential active attack",
        ThreatLevel.CRITICAL: "URGENT: Disconnect from network immediately"
    }
    
    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        throttle_minutes: int = 15,
        dry_run: bool = False
    ):
        """Initialize Telegram alerter.
        
        Args:
            bot_token: Telegram bot token (defaults to TELEGRAM_BOT_TOKEN env var)
            chat_id: Chat ID to send alerts to (defaults to TELEGRAM_CHAT_ID env var)
            throttle_minutes: Minimum minutes between similar alerts
            dry_run: If True, only log alerts without sending to Telegram
        """
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
        self.throttle_minutes = throttle_minutes
        self.dry_run = dry_run
        
        self.logger = get_logger("privaseeai_security.alerting.telegram")
        
        # Track recent alerts for throttling
        # Key: (attack_type, threat_level), Value: timestamp of last alert
        self._recent_alerts: Dict[tuple, datetime] = {}
        
        # Validate configuration
        if not self.dry_run:
            if not self.bot_token:
                self.logger.warning(
                    "TELEGRAM_BOT_TOKEN not set - running in dry-run mode"
                )
                self.dry_run = True
            if not self.chat_id:
                self.logger.warning(
                    "TELEGRAM_CHAT_ID not set - running in dry-run mode"
                )
                self.dry_run = True
        
        self.logger.info(
            f"TelegramAlerter initialized (dry_run={self.dry_run}, "
            f"throttle={throttle_minutes}min)"
        )
    
    def send_threat_alert(
        self,
        threat,  # Type hint removed - accepts any threat detection object
        force: bool = False
    ) -> bool:
        """Send threat alert to Telegram.
        
        Args:
            threat: Threat detection object with attributes: threat_level, attack_type, 
                   indicators, timestamp, details (optional), source_monitor (optional)
            force: If True, bypass throttling
            
        Returns:
            True if alert was sent, False if throttled or failed
        """
        # Check if alert should be throttled
        if not force and self._is_throttled(threat):
            self.logger.debug(
                f"Alert throttled: {threat.attack_type} ({threat.threat_level.value})"
            )
            return False
        
        # Format alert message
        message = self._format_alert(threat)
        
        # Send alert
        if self.dry_run:
            self.logger.info(f"DRY RUN - Would send alert:\n{message}")
            success = True
        else:
            success = self._send_to_telegram(message)
        
        # Update throttle tracking
        if success:
            alert_key = (threat.attack_type, threat.threat_level)
            self._recent_alerts[alert_key] = datetime.now()
        
        return success
    
    def send_custom_alert(
        self,
        title: str,
        message: str,
        severity: ThreatLevel = ThreatLevel.MEDIUM
    ) -> bool:
        """Send custom formatted alert.
        
        Args:
            title: Alert title
            message: Alert message body
            severity: Severity level
            
        Returns:
            True if alert was sent successfully
        """
        emoji = self.SEVERITY_EMOJI.get(severity, "ℹ️")
        formatted_message = f"{emoji} {title}\n\n{message}"
        
        if self.dry_run:
            self.logger.info(f"DRY RUN - Would send custom alert:\n{formatted_message}")
            return True
        else:
            return self._send_to_telegram(formatted_message)
    
    def _is_throttled(self, threat) -> bool:
        """Check if alert should be throttled.
        
        Args:
            threat: Threat to check (any object with attack_type and threat_level)
            
        Returns:
            True if alert should be throttled
        """
        alert_key = (threat.attack_type, threat.threat_level)
        
        if alert_key not in self._recent_alerts:
            return False
        
        last_alert = self._recent_alerts[alert_key]
        time_since_last = datetime.now() - last_alert
        
        return time_since_last < timedelta(minutes=self.throttle_minutes)
    
    def _format_alert(self, threat) -> str:
        """Format threat detection as alert message.
        
        Args:
            threat: Threat to format (any object with required attributes)
            
        Returns:
            Formatted alert message
        """
        emoji = self.SEVERITY_EMOJI.get(threat.threat_level, "⚠️")
        severity_name = threat.threat_level.value.upper()
        
        # Build message
        lines = [
            f"{emoji} {severity_name} THREAT DETECTED",
            "",
            f"Type: {threat.attack_type}",
            f"Severity: {severity_name}",
            f"Time: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]
        
        # Add source monitor if available
        if hasattr(threat, 'source_monitor') and threat.source_monitor:
            lines.append(f"Source: {threat.source_monitor}")
        
        # Add details section
        if hasattr(threat, 'details') and threat.details:
            lines.extend(["", "Details:", threat.details])
        
        # Add indicators
        if threat.indicators:
            lines.extend(["", "Indicators:"])
            for indicator in threat.indicators:
                lines.append(f"• {indicator}")
        
        # Add recommended action
        action = self.RECOMMENDED_ACTIONS.get(
            threat.threat_level,
            "Review and investigate"
        )
        lines.extend(["", f"Recommended action: {action}"])
        
        return "\n".join(lines)
    
    def _send_to_telegram(self, message: str) -> bool:
        """Send message to Telegram (stub for now - would use python-telegram-bot).
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully
        """
        # NOTE: In production, this would use python-telegram-bot library:
        # from telegram import Bot
        # bot = Bot(token=self.bot_token)
        # bot.send_message(chat_id=self.chat_id, text=message, parse_mode='HTML')
        
        self.logger.info(f"Sending Telegram alert to chat {self.chat_id}")
        self.logger.debug(f"Message content:\n{message}")
        
        # For now, simulate successful send
        # In production, wrap in try/except and handle telegram.error.TelegramError
        return True
    
    def clear_throttle_cache(self) -> None:
        """Clear throttle cache (useful for testing)."""
        self._recent_alerts.clear()
        self.logger.debug("Throttle cache cleared")
    
    def get_throttle_status(self) -> Dict[str, datetime]:
        """Get current throttle status.
        
        Returns:
            Dictionary mapping alert types to last alert timestamp
        """
        return {
            f"{attack_type}:{level.value}": timestamp
            for (attack_type, level), timestamp in self._recent_alerts.items()
        }
    
    def should_alert(
        self,
        threat_level: ThreatLevel,
        min_severity: ThreatLevel = ThreatLevel.HIGH
    ) -> bool:
        """Check if threat level warrants an alert.
        
        Args:
            threat_level: Threat level to check
            min_severity: Minimum severity to alert on
            
        Returns:
            True if threat should trigger alert
        """
        # Define severity ordering
        severity_order = {
            ThreatLevel.NONE: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4
        }
        
        return severity_order.get(threat_level, 0) >= severity_order.get(min_severity, 3)
