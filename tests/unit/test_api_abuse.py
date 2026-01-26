"""Unit tests for API Abuse Monitor."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from src.privaseeai_security.monitors.api_abuse import (
    APIAbuseMonitor,
    APIThreatDetection,
    ThreatLevel,
    APIRequest
)


@pytest.fixture
def monitor():
    """Create APIAbuseMonitor instance for testing."""
    return APIAbuseMonitor()


@pytest.fixture
def mock_datetime():
    """Mock datetime for time-based testing."""
    return datetime(2026, 1, 26, 10, 0, 0)


class TestAPIRequestTracking:
    """Test API request tracking functionality."""
    
    def test_track_api_requests(self, monitor, mock_datetime):
        """Test tracking API requests."""
        monitor.track_api_request(
            app_identifier="com.protonvpn.app",
            endpoint="/api/v1/location",
            timestamp=mock_datetime
        )
        
        assert "com.protonvpn.app" in monitor.request_history
        assert len(monitor.request_history["com.protonvpn.app"]) == 1
        
        request = monitor.request_history["com.protonvpn.app"][0]
        assert request.endpoint == "/api/v1/location"
        assert request.timestamp == mock_datetime
    
    def test_track_multiple_apps(self, monitor, mock_datetime):
        """Test tracking requests from multiple applications."""
        monitor.track_api_request("com.app1", "/api/data", mock_datetime)
        monitor.track_api_request("com.app2", "/api/sync", mock_datetime)
        monitor.track_api_request("com.app1", "/api/update", mock_datetime)
        
        assert len(monitor.request_history) == 2
        assert len(monitor.request_history["com.app1"]) == 2
        assert len(monitor.request_history["com.app2"]) == 1
    
    def test_track_request_with_error(self, monitor, mock_datetime):
        """Test tracking request with error response."""
        monitor.track_api_request(
            app_identifier="com.test.app",
            endpoint="/api/data",
            timestamp=mock_datetime,
            response_code=429,
            error_message="Rate limit exceeded"
        )
        
        request = monitor.request_history["com.test.app"][0]
        assert request.response_code == 429
        assert request.error_message == "Rate limit exceeded"


class TestRateLimitDetection:
    """Test rate limiting detection."""
    
    def test_identify_rate_limiting_cooldown(self, monitor):
        """Test parsing ProtonVPN cooldown rate limit errors."""
        log_entry = 'ERROR | API | User location request failed | {"error":"cooldown(2026-01-26 05:24:44 +0000)"}'
        
        threat = monitor.check_rate_limit_responses("com.protonvpn.app", log_entry)
        
        assert threat is not None
        assert threat.threat_level == ThreatLevel.HIGH
        assert threat.attack_type == "API_TRACKING"
        assert threat.pattern_type == "RATE_LIMITED"
        assert threat.endpoint == "/api/v1/location"
        assert any("cooldown" in indicator.lower() for indicator in threat.indicators)
    
    def test_identify_generic_rate_limit(self, monitor):
        """Test detecting generic rate limit responses."""
        log_entry = "HTTP 429: Too many requests to /api/data"
        
        threat = monitor.check_rate_limit_responses("com.test.app", log_entry)
        
        assert threat is not None
        assert threat.threat_level == ThreatLevel.MEDIUM
        assert threat.attack_type == "API_ABUSE"
        assert threat.pattern_type == "RATE_LIMITED"
    
    def test_no_rate_limit_in_normal_log(self, monitor):
        """Test that normal logs don't trigger rate limit detection."""
        log_entry = "INFO: API request successful to /api/servers"
        
        threat = monitor.check_rate_limit_responses("com.test.app", log_entry)
        
        assert threat is None
    
    def test_rate_limit_cooldown_servers_endpoint(self, monitor):
        """Test rate limit detection for servers endpoint."""
        log_entry = 'ERROR | API | Servers request failed | {"error":"cooldown(2026-01-26 06:00:00 +0000)"}'
        
        threat = monitor.check_rate_limit_responses("com.protonvpn.app", log_entry)
        
        assert threat is not None
        assert threat.endpoint == "/api/v1/servers"


class TestLocationTracking:
    """Test excessive location API tracking detection."""
    
    def test_detect_location_tracking(self, monitor):
        """Test detecting excessive location API calls."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add 12 location requests in 1 hour (exceeds threshold of 10)
        for i in range(12):
            monitor.track_api_request(
                app_identifier="com.tracking.app",
                endpoint="/api/v1/location",
                timestamp=base_time + timedelta(minutes=i*5)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            threat = monitor.detect_location_tracking("com.tracking.app", time_window_hours=1)
        
        assert threat is not None
        assert threat.threat_level == ThreatLevel.HIGH
        assert threat.attack_type == "LOCATION_TRACKING"
        assert threat.pattern_type == "EXCESSIVE_LOCATION_REQUESTS"
        assert threat.request_rate == 12.0
    
    def test_normal_location_usage_no_alert(self, monitor):
        """Test that normal location usage doesn't trigger alerts."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add 5 location requests (below threshold)
        for i in range(5):
            monitor.track_api_request(
                app_identifier="com.normal.app",
                endpoint="/api/location",
                timestamp=base_time + timedelta(minutes=i*10)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            threat = monitor.detect_location_tracking("com.normal.app")
        
        assert threat is None
    
    def test_geo_api_also_tracked(self, monitor):
        """Test that geo API endpoints are also tracked as location."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Mix of location and geo endpoints
        for i in range(6):
            endpoint = "/api/location" if i % 2 == 0 else "/api/geo/position"
            monitor.track_api_request(
                app_identifier="com.tracking.app",
                endpoint=endpoint,
                timestamp=base_time + timedelta(minutes=i*5)
            )
        
        # Add 6 more to exceed threshold
        for i in range(6):
            monitor.track_api_request(
                app_identifier="com.tracking.app",
                endpoint="/api/geo/current",
                timestamp=base_time + timedelta(minutes=30 + i*2)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            threat = monitor.detect_location_tracking("com.tracking.app")
        
        assert threat is not None
        assert threat.request_rate == 12.0


class TestBurstDetection:
    """Test burst request pattern detection."""
    
    def test_detect_burst_pattern(self, monitor):
        """Test detecting burst of many requests in short time."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add 25 requests in 5 minutes (exceeds BURST_THRESHOLD of 20)
        for i in range(25):
            monitor.track_api_request(
                app_identifier="com.burst.app",
                endpoint=f"/api/data/{i}",
                timestamp=base_time + timedelta(seconds=i*10)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(minutes=5)
            threats = monitor.analyze_request_patterns("com.burst.app")
        
        # Should detect burst pattern
        burst_threats = [t for t in threats if t.attack_type == "API_BURST"]
        assert len(burst_threats) == 1
        assert burst_threats[0].threat_level == ThreatLevel.MEDIUM
        assert burst_threats[0].pattern_type == "BURST"
    
    def test_normal_request_rate_no_burst(self, monitor):
        """Test that normal request rates don't trigger burst detection."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add 10 requests in 5 minutes (below threshold)
        for i in range(10):
            monitor.track_api_request(
                app_identifier="com.normal.app",
                endpoint="/api/sync",
                timestamp=base_time + timedelta(seconds=i*30)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(minutes=5)
            threats = monitor.analyze_request_patterns("com.normal.app")
        
        burst_threats = [t for t in threats if t.attack_type == "API_BURST"]
        assert len(burst_threats) == 0


class TestBackgroundActivityDetection:
    """Test background activity detection during idle hours."""
    
    def test_detect_background_activity(self, monitor):
        """Test detecting requests during idle hours (11pm-6am)."""
        # Add 6 requests during idle hours
        for hour in [23, 0, 1, 2, 3, 4]:  # 11pm to 4am
            monitor.track_api_request(
                app_identifier="com.sneaky.app",
                endpoint="/api/track",
                timestamp=datetime(2026, 1, 26, hour, 30, 0)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2026, 1, 26, 12, 0, 0)
            threats = monitor.analyze_request_patterns("com.sneaky.app")
        
        background_threats = [t for t in threats if t.attack_type == "BACKGROUND_TRACKING"]
        assert len(background_threats) == 1
        assert background_threats[0].threat_level == ThreatLevel.MEDIUM
        assert background_threats[0].pattern_type == "BACKGROUND"
    
    def test_daytime_activity_no_alert(self, monitor):
        """Test that daytime activity doesn't trigger background detection."""
        # Add requests during daytime (8am-10pm)
        for hour in [8, 10, 14, 18, 20]:
            monitor.track_api_request(
                app_identifier="com.normal.app",
                endpoint="/api/data",
                timestamp=datetime(2026, 1, 26, hour, 0, 0)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = datetime(2026, 1, 26, 22, 0, 0)
            threats = monitor.analyze_request_patterns("com.normal.app")
        
        background_threats = [t for t in threats if t.attack_type == "BACKGROUND_TRACKING"]
        assert len(background_threats) == 0


class TestRequestStatistics:
    """Test request statistics calculation."""
    
    def test_calculate_request_frequency(self, monitor):
        """Test calculating requests per time window."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add 12 requests in 24 hours
        for i in range(12):
            monitor.track_api_request(
                app_identifier="com.test.app",
                endpoint="/api/sync",
                timestamp=base_time + timedelta(hours=i*2)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=24)
            stats = monitor.get_request_statistics("com.test.app", time_window_hours=24)
        
        assert stats["total_requests"] == 12
        assert stats["requests_per_hour"] == 0.5
    
    def test_statistics_for_unknown_app(self, monitor):
        """Test statistics for app with no tracked requests."""
        stats = monitor.get_request_statistics("com.unknown.app")
        
        assert stats["total_requests"] == 0
        assert stats["requests_per_hour"] == 0.0
        assert stats["unique_endpoints"] == 0
        assert stats["rate_limited"] is False
    
    def test_unique_endpoints_count(self, monitor):
        """Test counting unique endpoints."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add requests to 3 different endpoints
        monitor.track_api_request("com.test.app", "/api/v1/data", base_time)
        monitor.track_api_request("com.test.app", "/api/v1/sync", base_time)
        monitor.track_api_request("com.test.app", "/api/v1/data", base_time)
        monitor.track_api_request("com.test.app", "/api/v1/update", base_time)
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            stats = monitor.get_request_statistics("com.test.app")
        
        assert stats["total_requests"] == 4
        assert stats["unique_endpoints"] == 3
    
    def test_rate_limited_flag(self, monitor):
        """Test detection of rate limited status."""
        base_time = datetime(2026, 1, 26, 10, 0, 0)
        
        # Add normal request
        monitor.track_api_request(
            "com.test.app",
            "/api/data",
            base_time,
            response_code=200
        )
        
        # Add rate limited request
        monitor.track_api_request(
            "com.test.app",
            "/api/data",
            base_time + timedelta(minutes=1),
            response_code=429,
            error_message="cooldown(2026-01-26 11:00:00 +0000)"
        )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            stats = monitor.get_request_statistics("com.test.app")
        
        assert stats["rate_limited"] is True


class TestComprehensivePatternAnalysis:
    """Test comprehensive pattern analysis."""
    
    def test_analyze_multiple_threats(self, monitor):
        """Test detecting multiple threat patterns simultaneously."""
        base_time = datetime(2026, 1, 26, 2, 0, 0)  # 2am (idle time)
        
        # Add burst of location requests during idle hours
        for i in range(15):
            monitor.track_api_request(
                app_identifier="com.suspicious.app",
                endpoint="/api/location",
                timestamp=base_time + timedelta(minutes=i)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(minutes=20)
            threats = monitor.analyze_request_patterns("com.suspicious.app")
        
        # Should detect both location tracking and background activity
        attack_types = [t.attack_type for t in threats]
        assert "LOCATION_TRACKING" in attack_types
        assert "BACKGROUND_TRACKING" in attack_types
    
    def test_no_threats_for_normal_usage(self, monitor):
        """Test that normal usage patterns don't trigger alerts."""
        base_time = datetime(2026, 1, 26, 14, 0, 0)  # 2pm (daytime)
        
        # Add reasonable number of requests
        for i in range(5):
            monitor.track_api_request(
                app_identifier="com.normal.app",
                endpoint="/api/sync",
                timestamp=base_time + timedelta(minutes=i*10)
            )
        
        with patch('src.privaseeai_security.monitors.api_abuse.datetime') as mock_dt:
            mock_dt.now.return_value = base_time + timedelta(hours=1)
            threats = monitor.analyze_request_patterns("com.normal.app")
        
        assert len(threats) == 0
