"""Guards the dashboard's fabricated-data gate.

The dashboard has no data path to the detection engine. Its seed data is
invented, and it was previously served unconditionally -- so a page load
rendered freshly-timestamped HIGH severity "threats" on a machine with no
device attached. These tests pin the property that made that possible shut:

    without PRIVASEE_DEMO=1, no endpoint may return a threat, device,
    monitor or activity entry, and the simulation endpoints must not exist.
"""

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# The dashboard lives outside the installed package, at the repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _load_dashboard(monkeypatch, demo: bool):
    """Import dashboard.api.main with PRIVASEE_DEMO set or cleared.

    DEMO_MODE is read at import time, so the module must be reloaded rather
    than patched after the fact.
    """
    if demo:
        monkeypatch.setenv("PRIVASEE_DEMO", "1")
    else:
        monkeypatch.delenv("PRIVASEE_DEMO", raising=False)
    module = importlib.import_module("dashboard.api.main")
    return importlib.reload(module)


@pytest.fixture
def default_client(monkeypatch):
    """Client with the flag unset -- the shipping default."""
    module = _load_dashboard(monkeypatch, demo=False)
    with TestClient(module.app) as client:
        yield client


@pytest.fixture
def demo_client(monkeypatch):
    module = _load_dashboard(monkeypatch, demo=True)
    with TestClient(module.app) as client:
        yield client


class TestDefaultIsEmpty:
    """Without the opt-in, nothing fabricated may reach a caller."""

    @pytest.mark.parametrize(
        "endpoint",
        ["/api/threats", "/api/devices", "/api/monitors", "/api/activity"],
    )
    def test_collections_are_empty(self, default_client, endpoint):
        response = default_client.get(endpoint)
        assert response.status_code == 200
        assert response.json() == [], f"{endpoint} served fabricated data by default"

    def test_stats_are_all_zero(self, default_client):
        stats = default_client.get("/api/stats").json()
        for field in (
            "total_devices",
            "active_devices",
            "total_threats",
            "critical_threats",
            "monitors_running",
        ):
            assert stats[field] == 0, f"{field} was non-zero without a data source"

    def test_health_declares_no_data_source(self, default_client):
        health = default_client.get("/api/health").json()
        assert health["demo_mode"] is False
        assert health["data_source"] == "none"

    @pytest.mark.parametrize(
        "endpoint",
        ["/api/simulate/threat", "/api/simulate/start", "/api/simulate/stop"],
    )
    def test_simulation_endpoints_are_gated(self, default_client, endpoint):
        assert default_client.post(endpoint).status_code == 404

    def test_page_states_it_has_no_data_source(self, default_client):
        body = default_client.get("/").text
        assert "No data source connected" in body
        assert "DEMO MODE" not in body


class TestDemoModeIsLabelled:
    """With the opt-in, data may appear -- but never unlabelled."""

    def test_threats_are_served(self, demo_client):
        assert len(demo_client.get("/api/threats").json()) > 0

    def test_page_carries_the_demo_banner(self, demo_client):
        body = demo_client.get("/").text
        assert "DEMO MODE" in body
        assert "fabricated" in body

    def test_health_declares_demo_mode(self, demo_client):
        assert demo_client.get("/api/health").json()["demo_mode"] is True

    def test_simulation_is_available(self, demo_client):
        assert demo_client.post("/api/simulate/threat").status_code == 200

    def test_no_real_person_name_in_fixtures(self, demo_client):
        """Fabricated alerts must not be attributed to a real device owner."""
        body = demo_client.get("/api/threats").text + demo_client.get("/api/devices").text
        assert "Mark" not in body
