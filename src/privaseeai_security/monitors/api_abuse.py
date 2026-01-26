"""API Abuse Monitor for detecting application API tracking and abuse patterns.

This module monitors application API usage to detect:
- Rate limiting responses indicating tracking attempts
- Excessive location API calls
- Background API activity during device idle
- Abnormal request burst patterns
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional
import json

from ..config import Config
from ..logger import get_logger
from ..crypto.cert_validator import ThreatLevel


@dataclass
class APIThreatDetection:
    """Data class for API threat detection results."""
    app_identifier: str
    endpoint: str
    threat_level: ThreatLevel
    attack_type: str
    indicators: List[str]
    timestamp: datetime
    request_rate: Optional[float] = None
    pattern_type: Optional[str] = None
    details: Optional[str] = None


@dataclass
class APIRequest:
    """Data class for API request tracking."""
    app_identifier: str
    endpoint: str
    timestamp: datetime
    response_code: Optional[int] = None
    error_message: Optional[str] = None


class APIAbuseMonitor:
    """Monitor application API usage patterns for abuse and tracking.
    
    This monitor tracks API requests from applications and detects:
    - Rate limiting responses (indicating tracking/abuse)
    - Excessive location API usage
    - Background API activity during idle hours
    - Burst request patterns
    
    Example:
        monitor = APIAbuseMonitor()
        monitor.track_api_request("com.protonvpn.app", "/api/v1/location", datetime.now())
        threats = monitor.analyze_request_patterns()
    """
    
    # Location API request thresholds
    LOCATION_REQUESTS_PER_HOUR_THRESHOLD = 10
    
    # Background activity detection (11pm-6am)
    IDLE_START_HOUR = 23  # 11pm
    IDLE_END_HOUR = 6     # 6am
    
    # Burst detection: requests in short time
    BURST_WINDOW_MINUTES = 5
    BURST_THRESHOLD = 20
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize API Abuse Monitor.
        
        Args:
            config: Configuration object. If None, creates default Config.
        """
        self.config = config or Config()
        self.logger = get_logger("privaseeai_security.monitors.api_abuse")
        
        # Track all API requests by app
        self.request_history: Dict[str, List[APIRequest]] = {}
        
        # Track rate limiting events
        self.rate_limit_events: List[APIThreatDetection] = []
        
        self.logger.info("APIAbuseMonitor initialized")
    
    def track_api_request(
        self,
        app_identifier: str,
        endpoint: str,
        timestamp: datetime,
        response_code: Optional[int] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Record an API request for tracking.
        
        Args:
            app_identifier: Application bundle ID or identifier
            endpoint: API endpoint path
            timestamp: When the request was made
            response_code: HTTP response code (if available)
            error_message: Error message from response (if any)
        """
        request = APIRequest(
            app_identifier=app_identifier,
            endpoint=endpoint,
            timestamp=timestamp,
            response_code=response_code,
            error_message=error_message
        )
        
        if app_identifier not in self.request_history:
            self.request_history[app_identifier] = []
        
        self.request_history[app_identifier].append(request)
        
        self.logger.debug(
            f"Tracked API request: {app_identifier} -> {endpoint}"
        )
    
    def check_rate_limit_responses(
        self,
        app_identifier: str,
        log_entry: str
    ) -> Optional[APIThreatDetection]:
        """Parse rate limit errors from application logs.
        
        Detects rate limiting responses which indicate the app is making
        excessive requests, potentially for tracking purposes.
        
        Args:
            app_identifier: Application making the request
            log_entry: Raw log entry to parse
            
        Returns:
            APIThreatDetection if rate limiting detected, None otherwise
        """
        # Check for cooldown errors (ProtonVPN format)
        if "cooldown(" in log_entry.lower():
            try:
                # Extract cooldown timestamp
                # Format: {"error":"cooldown(2026-01-26 05:24:44 +0000)"}
                start_idx = log_entry.find("cooldown(") + 9
                end_idx = log_entry.find(")", start_idx)
                cooldown_str = log_entry[start_idx:end_idx]
                
                # Parse endpoint from log
                endpoint = "unknown"
                if "location" in log_entry.lower():
                    endpoint = "/api/v1/location"
                elif "servers" in log_entry.lower():
                    endpoint = "/api/v1/servers"
                
                indicators = [
                    f"Rate limit cooldown until: {cooldown_str}",
                    "API abuse detected - excessive requests"
                ]
                
                return APIThreatDetection(
                    app_identifier=app_identifier,
                    endpoint=endpoint,
                    threat_level=ThreatLevel.HIGH,
                    attack_type="API_TRACKING",
                    indicators=indicators,
                    timestamp=datetime.now(),
                    pattern_type="RATE_LIMITED",
                    details=f"Application is rate-limited, indicating excessive API usage for potential tracking"
                )
            except Exception as e:
                self.logger.error(f"Error parsing cooldown: {e}")
        
        # Check for generic rate limit responses
        if any(phrase in log_entry.lower() for phrase in ["rate limit", "too many requests", "429"]):
            return APIThreatDetection(
                app_identifier=app_identifier,
                endpoint="unknown",
                threat_level=ThreatLevel.MEDIUM,
                attack_type="API_ABUSE",
                indicators=["Rate limit response detected"],
                timestamp=datetime.now(),
                pattern_type="RATE_LIMITED"
            )
        
        return None
    
    def detect_location_tracking(
        self,
        app_identifier: str,
        time_window_hours: int = 1
    ) -> Optional[APIThreatDetection]:
        """Identify excessive location API calls.
        
        Args:
            app_identifier: Application to check
            time_window_hours: Time window to analyze (default 1 hour)
            
        Returns:
            APIThreatDetection if excessive location tracking detected
        """
        if app_identifier not in self.request_history:
            return None
        
        now = datetime.now()
        cutoff_time = now - timedelta(hours=time_window_hours)
        
        # Filter for recent location API requests
        location_requests = [
            req for req in self.request_history[app_identifier]
            if req.timestamp >= cutoff_time
            and ("location" in req.endpoint.lower() or "geo" in req.endpoint.lower())
        ]
        
        request_count = len(location_requests)
        
        if request_count > self.LOCATION_REQUESTS_PER_HOUR_THRESHOLD:
            request_rate = request_count / time_window_hours
            
            return APIThreatDetection(
                app_identifier=app_identifier,
                endpoint="location_api",
                threat_level=ThreatLevel.HIGH,
                attack_type="LOCATION_TRACKING",
                indicators=[
                    f"{request_count} location requests in {time_window_hours} hour(s)",
                    f"Rate: {request_rate:.1f} requests/hour",
                    f"Threshold: {self.LOCATION_REQUESTS_PER_HOUR_THRESHOLD} requests/hour"
                ],
                timestamp=now,
                request_rate=request_rate,
                pattern_type="EXCESSIVE_LOCATION_REQUESTS"
            )
        
        return None
    
    def analyze_request_patterns(
        self,
        app_identifier: str
    ) -> List[APIThreatDetection]:
        """Analyze request patterns for anomalies.
        
        Detects:
        - Burst patterns (many requests in short time)
        - Background activity during idle hours
        - Unusual request frequencies
        
        Args:
            app_identifier: Application to analyze
            
        Returns:
            List of threat detections found
        """
        threats = []
        
        if app_identifier not in self.request_history:
            return threats
        
        # Check for burst patterns
        burst_threat = self._detect_burst_pattern(app_identifier)
        if burst_threat:
            threats.append(burst_threat)
        
        # Check for background activity
        background_threat = self._detect_background_activity(app_identifier)
        if background_threat:
            threats.append(background_threat)
        
        # Check for location tracking
        location_threat = self.detect_location_tracking(app_identifier)
        if location_threat:
            threats.append(location_threat)
        
        return threats
    
    def _detect_burst_pattern(
        self,
        app_identifier: str
    ) -> Optional[APIThreatDetection]:
        """Detect burst request patterns.
        
        Args:
            app_identifier: Application to check
            
        Returns:
            APIThreatDetection if burst detected
        """
        now = datetime.now()
        cutoff_time = now - timedelta(minutes=self.BURST_WINDOW_MINUTES)
        
        recent_requests = [
            req for req in self.request_history[app_identifier]
            if req.timestamp >= cutoff_time
        ]
        
        if len(recent_requests) >= self.BURST_THRESHOLD:
            request_rate = len(recent_requests) / (self.BURST_WINDOW_MINUTES / 60)
            
            return APIThreatDetection(
                app_identifier=app_identifier,
                endpoint="multiple",
                threat_level=ThreatLevel.MEDIUM,
                attack_type="API_BURST",
                indicators=[
                    f"{len(recent_requests)} requests in {self.BURST_WINDOW_MINUTES} minutes",
                    f"Rate: {request_rate:.1f} requests/hour",
                    "Possible data exfiltration or scanning activity"
                ],
                timestamp=now,
                request_rate=request_rate,
                pattern_type="BURST"
            )
        
        return None
    
    def _detect_background_activity(
        self,
        app_identifier: str
    ) -> Optional[APIThreatDetection]:
        """Detect background API activity during idle hours (11pm-6am).
        
        Args:
            app_identifier: Application to check
            
        Returns:
            APIThreatDetection if suspicious background activity detected
        """
        # Check last 24 hours
        now = datetime.now()
        cutoff_time = now - timedelta(hours=24)
        
        idle_requests = []
        for req in self.request_history[app_identifier]:
            if req.timestamp >= cutoff_time:
                hour = req.timestamp.hour
                # Check if during idle hours (11pm-6am)
                if hour >= self.IDLE_START_HOUR or hour < self.IDLE_END_HOUR:
                    idle_requests.append(req)
        
        if len(idle_requests) >= 5:  # Threshold for suspicious activity
            return APIThreatDetection(
                app_identifier=app_identifier,
                endpoint="multiple",
                threat_level=ThreatLevel.MEDIUM,
                attack_type="BACKGROUND_TRACKING",
                indicators=[
                    f"{len(idle_requests)} requests during idle hours (11pm-6am)",
                    "Unusual background activity when device should be idle",
                    "Possible covert tracking or data collection"
                ],
                timestamp=now,
                pattern_type="BACKGROUND"
            )
        
        return None
    
    def get_request_statistics(
        self,
        app_identifier: str,
        time_window_hours: int = 24
    ) -> Dict:
        """Get request statistics for an application.
        
        Args:
            app_identifier: Application to analyze
            time_window_hours: Time window to analyze
            
        Returns:
            Dictionary with statistics
        """
        if app_identifier not in self.request_history:
            return {
                "total_requests": 0,
                "requests_per_hour": 0.0,
                "unique_endpoints": 0,
                "rate_limited": False
            }
        
        now = datetime.now()
        cutoff_time = now - timedelta(hours=time_window_hours)
        
        recent_requests = [
            req for req in self.request_history[app_identifier]
            if req.timestamp >= cutoff_time
        ]
        
        unique_endpoints = len(set(req.endpoint for req in recent_requests))
        rate_limited = any(
            req.error_message and "cooldown" in req.error_message.lower()
            for req in recent_requests
        )
        
        return {
            "total_requests": len(recent_requests),
            "requests_per_hour": len(recent_requests) / time_window_hours,
            "unique_endpoints": unique_endpoints,
            "rate_limited": rate_limited
        }
