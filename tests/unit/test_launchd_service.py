"""Test launchd service and daemon functionality."""

import subprocess
import sys
from pathlib import Path
import pytest


# Get repository root
REPO_ROOT = Path(__file__).parent.parent.parent


def test_plist_file_exists():
    """Test that the plist file exists."""
    plist_path = REPO_ROOT / "com.privaseeai.security.plist"
    assert plist_path.exists(), "com.privaseeai.security.plist not found"


def test_plist_is_valid_xml():
    """Test that the plist file is valid XML."""
    import xml.etree.ElementTree as ET
    
    plist_path = REPO_ROOT / "com.privaseeai.security.plist"
    tree = ET.parse(plist_path)
    root = tree.getroot()
    
    assert root.tag == "plist", "Root element should be plist"
    assert root.attrib.get("version") == "1.0", "plist version should be 1.0"


def test_plist_has_required_keys():
    """Test that the plist has all required launchd keys."""
    import xml.etree.ElementTree as ET
    
    plist_path = REPO_ROOT / "com.privaseeai.security.plist"
    tree = ET.parse(plist_path)
    
    # Check for required keys
    required_keys = [
        "Label",
        "ProgramArguments",
        "RunAtLoad",
        "KeepAlive",
        "ThrottleInterval",
        "StandardOutPath",
        "StandardErrorPath",
        "WorkingDirectory",
    ]
    
    plist_text = ET.tostring(tree.getroot(), encoding='unicode')
    
    for key in required_keys:
        assert f"<key>{key}</key>" in plist_text, f"Missing required key: {key}"


def test_plist_program_arguments():
    """Test that ProgramArguments is correctly configured."""
    import xml.etree.ElementTree as ET
    
    plist_path = REPO_ROOT / "com.privaseeai.security.plist"
    tree = ET.parse(plist_path)
    
    plist_text = ET.tostring(tree.getroot(), encoding='unicode')
    
    # Should use python3 -m privaseeai_security.orchestrator
    assert "python3" in plist_text, "Should use python3"
    assert "privaseeai_security.orchestrator" in plist_text, "Should run orchestrator module"


def test_orchestrator_has_main_block():
    """Test that orchestrator.py has __main__ block for daemon mode."""
    from privaseeai_security import orchestrator
    
    # Check that the module has the main block
    import inspect
    source = inspect.getsource(orchestrator)
    
    assert 'if __name__ == "__main__"' in source, "orchestrator.py should have __main__ block"
    assert '_run_daemon' in source, "orchestrator.py should have _run_daemon function"


def test_orchestrator_can_be_imported():
    """Test that the orchestrator module can be imported."""
    from privaseeai_security.orchestrator import ThreatOrchestrator
    
    assert ThreatOrchestrator is not None, "Should be able to import ThreatOrchestrator"


def test_daemon_module_exists():
    """Test that daemon.py module exists as alternative."""
    from privaseeai_security import daemon
    
    assert daemon is not None, "daemon module should exist"
    assert hasattr(daemon, 'main'), "daemon should have main function"


def test_launchd_guide_exists():
    """Test that the LAUNCHD_SERVICE_GUIDE.md exists."""
    guide_path = REPO_ROOT / "LAUNCHD_SERVICE_GUIDE.md"
    assert guide_path.exists(), "LAUNCHD_SERVICE_GUIDE.md not found"
    
    # Check it has key sections
    content = guide_path.read_text()
    assert "Installation Steps" in content
    assert "Loading and Managing the Service" in content
    assert "Testing the Service" in content
    assert "Troubleshooting" in content


@pytest.mark.slow
def test_orchestrator_module_can_run():
    """Test that orchestrator can be run as a module (with quick timeout)."""
    # This test tries to run the module but times out quickly
    # Just verifying it starts without import errors
    
    proc = subprocess.Popen(
        [sys.executable, "-m", "privaseeai_security.orchestrator"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    try:
        # Let it run for 2 seconds
        stdout, stderr = proc.communicate(timeout=2)
        # If we get here, process exited early (might be an error)
        pytest.fail(f"Process exited unexpectedly: {stderr}")
    except subprocess.TimeoutExpired:
        # This is expected - the daemon should keep running
        proc.kill()
        stdout, stderr = proc.communicate()
        
        # Check for import errors or other startup failures in output
        combined = (stdout + stderr).lower()
        assert "traceback" not in combined and "modulenotfounderror" not in combined, \
            f"Module had errors: {stdout}\n{stderr}"
