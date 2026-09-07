"""Telegram delivery must actually deliver, or report failure.

`_send_to_telegram` previously logged and returned True. Every caller then
recorded a successful delivery for a message that was never sent, so a user
who configured a bot token saw "alert sent" in the logs and received nothing.
These tests pin the inverse: True only on real acceptance, False on every
failure path, and no throttle entry written for an alert that did not land.
"""

import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest

from privaseeai_security.alerting.telegram import TelegramAlerter
from privaseeai_security.crypto.cert_validator import ThreatLevel


def _threat(attack_type="LOCALHOST_VPN_ROUTING", level=ThreatLevel.CRITICAL):
    return SimpleNamespace(
        threat_level=level,
        attack_type=attack_type,
        indicators=["TEST_INDICATOR"],
        timestamp=datetime.now(),
        details="synthetic threat for delivery tests",
    )


@pytest.fixture
def alerter():
    """A configured, non-dry-run alerter. Delivery itself is stubbed per test."""
    return TelegramAlerter(bot_token="test-token", chat_id="12345", dry_run=False)


class TestDeliveryOutcome:
    def test_returns_true_only_when_delivery_succeeds(self, alerter, monkeypatch):
        async def ok(message):
            return None

        monkeypatch.setattr(alerter, "_deliver", ok)
        assert alerter._send_to_telegram("hello") is True

    def test_returns_false_when_delivery_always_fails(self, alerter, monkeypatch):
        from telegram.error import TelegramError

        async def boom(message):
            raise TelegramError("network down")

        monkeypatch.setattr(alerter, "_deliver", boom)
        monkeypatch.setattr("time.sleep", lambda _: None)  # don't wait out backoff

        assert alerter._send_to_telegram("hello") is False

    def test_retries_then_succeeds(self, alerter, monkeypatch):
        from telegram.error import TelegramError

        attempts = []

        async def flaky(message):
            attempts.append(1)
            if len(attempts) < 2:
                raise TelegramError("transient")
            return None

        monkeypatch.setattr(alerter, "_deliver", flaky)
        monkeypatch.setattr("time.sleep", lambda _: None)

        assert alerter._send_to_telegram("hello") is True
        assert len(attempts) == 2

    def test_retry_count_is_bounded(self, alerter, monkeypatch):
        from telegram.error import TelegramError

        attempts = []

        async def boom(message):
            attempts.append(1)
            raise TelegramError("still down")

        monkeypatch.setattr(alerter, "_deliver", boom)
        monkeypatch.setattr("time.sleep", lambda _: None)

        alerter._send_to_telegram("hello")
        assert len(attempts) == alerter.max_send_attempts

    def test_missing_credentials_reports_failure(self, monkeypatch):
        """Never claim success when there is nowhere to send."""
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)

        alerter = TelegramAlerter(bot_token="tok", chat_id="1", dry_run=False)
        alerter.bot_token = None

        assert alerter._send_to_telegram("hello") is False

    def test_timeout_is_a_failure_not_a_success(self, alerter, monkeypatch):
        async def hang(message):
            await asyncio.sleep(60)

        monkeypatch.setattr(alerter, "_deliver", hang)
        monkeypatch.setattr("time.sleep", lambda _: None)
        alerter.send_timeout_seconds = 0.01
        alerter.max_send_attempts = 1

        assert alerter._send_to_telegram("hello") is False


class TestThrottleIntegrity:
    """A failed send must not consume the throttle slot."""

    def test_failed_send_does_not_record_throttle(self, alerter, monkeypatch):
        from telegram.error import TelegramError

        async def boom(message):
            raise TelegramError("network down")

        monkeypatch.setattr(alerter, "_deliver", boom)
        monkeypatch.setattr("time.sleep", lambda _: None)

        threat = _threat()
        assert alerter.send_threat_alert(threat) is False
        assert alerter._recent_alerts == {}, (
            "a failed delivery recorded a phantom success, which would "
            "throttle the retry of a real alert"
        )

    def test_successful_send_records_throttle(self, alerter, monkeypatch):
        async def ok(message):
            return None

        monkeypatch.setattr(alerter, "_deliver", ok)

        threat = _threat()
        assert alerter.send_threat_alert(threat) is True
        assert len(alerter._recent_alerts) == 1


class TestCallableFromEventLoop:
    """The orchestrator calls this synchronous method from inside a loop."""

    @pytest.mark.asyncio
    async def test_send_works_inside_a_running_event_loop(self, alerter, monkeypatch):
        delivered = []

        async def ok(message):
            delivered.append(message)

        monkeypatch.setattr(alerter, "_deliver", ok)

        # asyncio.run() would raise RuntimeError here; the thread fallback must not.
        assert alerter._send_to_telegram("from inside a loop") is True
        assert delivered == ["from inside a loop"]


class TestDryRunStillHonest:
    def test_dry_run_does_not_attempt_delivery(self, monkeypatch):
        alerter = TelegramAlerter(dry_run=True)

        async def must_not_run(message):  # pragma: no cover
            raise AssertionError("dry run attempted real delivery")

        monkeypatch.setattr(alerter, "_deliver", must_not_run)
        assert alerter.send_threat_alert(_threat()) is True
