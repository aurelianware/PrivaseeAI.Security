"""Unit tests for main module."""

import pytest
from unittest.mock import patch, MagicMock

from privaseeai_security.__main__ import health_check


class TestHealthCheck:
    """Test cases for health_check function."""

    def test_health_check_success(self):
        """Test health check returns True when config validates successfully."""
        # The default config should validate successfully
        result = health_check()
        assert result is True

    def test_health_check_failure_config_error(self):
        """Test health check returns False when config validation fails."""
        # Mock Config to raise an exception during validation
        with patch('privaseeai_security.__main__.Config') as mock_config:
            mock_instance = MagicMock()
            mock_instance.validate.side_effect = Exception("Validation error")
            mock_config.return_value = mock_instance
            
            result = health_check()
            assert result is False

    def test_health_check_failure_import_error(self):
        """Test health check returns False when Config cannot be imported."""
        # Mock Config to raise an exception on instantiation
        with patch('privaseeai_security.__main__.Config', side_effect=ImportError("Module not found")):
            result = health_check()
            assert result is False

    def test_health_check_prints_error_on_failure(self, capsys):
        """Test health check prints error message when it fails."""
        with patch('privaseeai_security.__main__.Config') as mock_config:
            mock_instance = MagicMock()
            mock_instance.validate.side_effect = Exception("Test error")
            mock_config.return_value = mock_instance
            
            result = health_check()
            
            # Check that error was printed to stderr
            captured = capsys.readouterr()
            assert "Health check failed: Test error" in captured.err
            assert result is False
