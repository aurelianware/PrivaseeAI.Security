"""
PrivaseeAI.Security Dashboard API

Minimal FastAPI application for Phase 5 web dashboard.
Provides REST API and WebSocket support for real-time threat monitoring.
"""

from datetime import datetime, timedelta
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import Request
from pydantic import BaseModel, Field
import uvicorn

# For Phase 5B: Replace with real database
# from sqlalchemy import create_engine
# from sqlalchemy.orm import Session

app = FastAPI(
    title="PrivaseeAI Security Dashboard",
    description="Real-time iOS threat detection and monitoring",
    version="0.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Mount static files and templates
static_path = Path(__file__).parent.parent / "static"
templates_path = Path(__file__).parent.parent / "templates"
static_path.mkdir(exist_ok=True)
templates_path.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_path)), name="static")
templates = Jinja2Templates(directory=str(templates_path))

# WebSocket connection manager for real-time updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

# ============================================================================
# Pydantic Models
# ============================================================================

class Device(BaseModel):
    id: str
    device_name: str
    device_model: str
    ios_version: str
    last_seen_at: datetime
    status: str = "active"
    threat_count: int = 0

class Threat(BaseModel):
    id: str
    device_id: str
    device_name: str
    threat_type: str
    severity: str
    title: str
    description: str
    detected_at: datetime
    status: str = "open"
    indicators: List[str] = []
    occurrences: int = 1

class MonitorStatus(BaseModel):
    monitor_name: str
    is_running: bool
    last_heartbeat: Optional[datetime]
    events_processed: int = 0
    threats_detected: int = 0
    status: str = "stopped"

class DashboardStats(BaseModel):
    total_devices: int
    active_devices: int
    total_threats: int
    critical_threats: int
    monitors_running: int
    last_updated: datetime

# ============================================================================
# Mock Data (Phase 5A - Replace with database in Phase 5B)
# ============================================================================

# Mock devices
mock_devices = [
    Device(
        id="device-1",
        device_name="Mark's iPhone",
        device_model="iPhone 16 Pro",
        ios_version="18.2",
        last_seen_at=datetime.now() - timedelta(minutes=2),
        status="active",
        threat_count=2
    ),
]

# Mock threats
mock_threats = [
    Threat(
        id="threat-1",
        device_id="device-1",
        device_name="Mark's iPhone",
        threat_type="VPN_MANIPULATION",
        severity="HIGH",
        title="WireGuard forced to TCP (UDP blocked)",
        description="VPN protocol manipulation detected. UDP traffic is being blocked, forcing fallback to TCP.",
        detected_at=datetime.now() - timedelta(hours=2),
        indicators=["UDP_BLOCKED", "TCP_FALLBACK"],
        status="open",
        occurrences=3
    ),
    Threat(
        id="threat-2",
        device_id="device-1",
        device_name="Mark's iPhone",
        threat_type="API_ABUSE",
        severity="MEDIUM",
        title="Location API rate limiting detected",
        description="Excessive location API requests being throttled. Possible tracking attempt.",
        detected_at=datetime.now() - timedelta(hours=5),
        indicators=["RATE_LIMITED", "LOCATION_TRACKING"],
        status="investigating",
        occurrences=1
    ),
]

# Mock monitor status
mock_monitors = [
    MonitorStatus(
        monitor_name="VPNIntegrityMonitor",
        is_running=True,
        last_heartbeat=datetime.now() - timedelta(seconds=30),
        events_processed=1247,
        threats_detected=3,
        status="running"
    ),
    MonitorStatus(
        monitor_name="APIAbuseMonitor",
        is_running=True,
        last_heartbeat=datetime.now() - timedelta(seconds=45),
        events_processed=892,
        threats_detected=1,
        status="running"
    ),
    MonitorStatus(
        monitor_name="CarrierCompromiseDetector",
        is_running=True,
        last_heartbeat=datetime.now() - timedelta(minutes=1),
        events_processed=45,
        threats_detected=0,
        status="running"
    ),
    MonitorStatus(
        monitor_name="CertificateValidator",
        is_running=False,
        last_heartbeat=datetime.now() - timedelta(hours=2),
        events_processed=23,
        threats_detected=0,
        status="stopped"
    ),
]

# ============================================================================
# API Routes
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/stats", response_model=DashboardStats)
async def get_stats():
    """Get overall dashboard statistics"""
    active_devices = len([d for d in mock_devices if d.status == "active"])
    critical_threats = len([t for t in mock_threats if t.severity == "CRITICAL" and t.status == "open"])
    running_monitors = len([m for m in mock_monitors if m.is_running])

    return DashboardStats(
        total_devices=len(mock_devices),
        active_devices=active_devices,
        total_threats=len([t for t in mock_threats if t.status == "open"]),
        critical_threats=critical_threats,
        monitors_running=running_monitors,
        last_updated=datetime.now()
    )

@app.get("/api/devices", response_model=List[Device])
async def get_devices(status: Optional[str] = Query(None)):
    """Get list of monitored devices"""
    devices = mock_devices
    if status:
        devices = [d for d in devices if d.status == status]
    return devices

@app.get("/api/devices/{device_id}", response_model=Device)
async def get_device(device_id: str):
    """Get specific device details"""
    device = next((d for d in mock_devices if d.id == device_id), None)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device

@app.get("/api/threats", response_model=List[Threat])
async def get_threats(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    limit: int = Query(100, le=1000)
):
    """Get list of threats with filtering"""
    threats = mock_threats

    if severity:
        threats = [t for t in threats if t.severity == severity]
    if status:
        threats = [t for t in threats if t.status == status]
    if device_id:
        threats = [t for t in threats if t.device_id == device_id]

    # Sort by severity and detection time
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    threats.sort(key=lambda t: (severity_order.get(t.severity, 4), -t.detected_at.timestamp()))

    return threats[:limit]

@app.get("/api/threats/{threat_id}", response_model=Threat)
async def get_threat(threat_id: str):
    """Get specific threat details"""
    threat = next((t for t in mock_threats if t.id == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat

@app.patch("/api/threats/{threat_id}/status")
async def update_threat_status(threat_id: str, status: str):
    """Update threat status (open, investigating, resolved, false_positive)"""
    threat = next((t for t in mock_threats if t.id == threat_id), None)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    if status not in ["open", "investigating", "resolved", "false_positive"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    threat.status = status

    # Broadcast update to WebSocket clients
    await manager.broadcast({
        "type": "threat_update",
        "threat_id": threat_id,
        "status": status,
        "timestamp": datetime.now().isoformat()
    })

    return {"success": True, "threat_id": threat_id, "status": status}

@app.get("/api/monitors", response_model=List[MonitorStatus])
async def get_monitors():
    """Get status of all monitors"""
    return mock_monitors

@app.post("/api/monitors/{monitor_name}/start")
async def start_monitor(monitor_name: str):
    """Start a monitor"""
    monitor = next((m for m in mock_monitors if m.monitor_name == monitor_name), None)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    monitor.is_running = True
    monitor.status = "running"
    monitor.last_heartbeat = datetime.now()

    await manager.broadcast({
        "type": "monitor_status",
        "monitor_name": monitor_name,
        "is_running": True,
        "timestamp": datetime.now().isoformat()
    })

    return {"success": True, "monitor_name": monitor_name, "status": "running"}

@app.post("/api/monitors/{monitor_name}/stop")
async def stop_monitor(monitor_name: str):
    """Stop a monitor"""
    monitor = next((m for m in mock_monitors if m.monitor_name == monitor_name), None)
    if not monitor:
        raise HTTPException(status_code=404, detail="Monitor not found")

    monitor.is_running = False
    monitor.status = "stopped"

    await manager.broadcast({
        "type": "monitor_status",
        "monitor_name": monitor_name,
        "is_running": False,
        "timestamp": datetime.now().isoformat()
    })

    return {"success": True, "monitor_name": monitor_name, "status": "stopped"}

# ============================================================================
# WebSocket for Real-Time Updates
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket connection for real-time threat updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and listen for client messages
            data = await websocket.receive_text()
            # Echo back for testing
            await websocket.send_json({
                "type": "pong",
                "timestamp": datetime.now().isoformat()
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ============================================================================
# Health Check
# ============================================================================

@app.get("/api/health")
async def health_check():
    """API health check"""
    return {
        "status": "healthy",
        "version": "0.3.0",
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
