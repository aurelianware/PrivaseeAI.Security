#!/usr/bin/env python3
"""
Demonstration script for crash recovery and graceful shutdown features.

This script shows:
1. State persistence across restarts
2. Graceful shutdown on SIGTERM/SIGINT
3. Alert queue draining
4. Exponential backoff retry
"""

import asyncio
import signal
import sys
from pathlib import Path
from datetime import datetime

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent / "src"))

from privaseeai_security.orchestrator import ThreatOrchestrator
from privaseeai_security.logger import setup_logger, get_logger


logger = get_logger(__name__)


async def main():
    """Run demo of crash recovery and shutdown features."""
    
    print("\n" + "="*70)
    print("PrivaseeAI Security Orchestrator - Crash Recovery Demo")
    print("="*70 + "\n")
    
    # Create a temporary directory for demo
    import tempfile
    tmpdir = Path(tempfile.mkdtemp(prefix="privasee_demo_"))
    state_file = tmpdir / "orchestrator_state.json"
    
    print(f"📁 Using temporary directory: {tmpdir}")
    print(f"💾 State file: {state_file}\n")
    
    # Create orchestrator with state persistence
    orchestrator = ThreatOrchestrator(
        backup_path=tmpdir / "backups",
        telegram_enabled=False,  # Disable for demo
        monitor_interval=2,
        scan_backups_on_start=False,
        state_file=state_file,
        max_retry_delay=8,  # Low for demo
    )
    
    print("🚀 Starting orchestrator...\n")
    await orchestrator.start()
    
    # Simulate some threat detection
    print("📊 Simulating threat detections...")
    orchestrator._total_threats = 5
    orchestrator._seen_threat_ids.add("threat_001")
    orchestrator._seen_threat_ids.add("threat_002")
    print(f"   Total threats: {orchestrator._total_threats}")
    print(f"   Seen threat IDs: {len(orchestrator._seen_threat_ids)}\n")
    
    # Get initial status
    status = orchestrator.get_status()
    print("📈 System Status:")
    print(f"   Running: {status.running}")
    print(f"   Started at: {status.started_at.strftime('%H:%M:%S')}")
    print(f"   Active monitors: {len([m for m in status.monitors.values() if m.name == 'running'])}")
    print(f"   Threats detected: {status.threats_detected}\n")
    
    # Setup signal handler for demo
    shutdown_event = asyncio.Event()
    
    def signal_handler(sig):
        """Handle shutdown signals."""
        sig_name = signal.Signals(sig).name
        print(f"\n📡 Received {sig_name}, initiating graceful shutdown...")
        shutdown_event.set()
    
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: signal_handler(s))
    
    print("⏳ Running for 5 seconds (press Ctrl+C to test graceful shutdown)...\n")
    
    try:
        # Wait for shutdown or timeout
        await asyncio.wait_for(shutdown_event.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        print("⏰ Timeout reached, shutting down...\n")
    
    # Graceful shutdown
    print("🛑 Stopping orchestrator gracefully...")
    await orchestrator.stop()
    
    # Verify state was saved
    print("\n💾 State Persistence Check:")
    if state_file.exists():
        print("   ✅ State file created successfully")
        import json
        with open(state_file) as f:
            state = json.load(f)
        print(f"   📊 Saved state:")
        print(f"      - Total threats: {state['total_threats']}")
        print(f"      - Seen threat IDs: {len(state['seen_threat_ids'])}")
        print(f"      - Saved at: {state['saved_at'][:19]}")
    else:
        print("   ❌ State file not found")
    
    # Demonstrate state restoration
    print("\n🔄 Demonstrating State Restoration:")
    print("   Creating new orchestrator instance...\n")
    
    orchestrator2 = ThreatOrchestrator(
        backup_path=tmpdir / "backups",
        telegram_enabled=False,
        monitor_interval=2,
        scan_backups_on_start=False,
        state_file=state_file,
    )
    
    await orchestrator2.start()
    
    print("   📊 Restored state:")
    print(f"      - Total threats: {orchestrator2._total_threats}")
    print(f"      - Seen threat IDs: {len(orchestrator2._seen_threat_ids)}")
    
    if orchestrator2._total_threats == 5:
        print("   ✅ State restored successfully!")
    else:
        print("   ❌ State restoration failed")
    
    await orchestrator2.stop()
    
    # Cleanup
    import shutil
    shutil.rmtree(tmpdir)
    
    print("\n" + "="*70)
    print("✅ Demo completed successfully!")
    print("="*70 + "\n")


if __name__ == "__main__":
    # Setup logging for demo
    setup_logger(level="INFO", log_format="text")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⌨️  Keyboard interrupt received")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
