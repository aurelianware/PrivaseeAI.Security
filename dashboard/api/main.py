"""
PrivaseeAI.Security Dashboard API

Minimal FastAPI application for Phase 5 web dashboard.
Provides REST API and WebSocket support for real-time threat monitoring.
"""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import random
import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, StreamingResponse
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

class ConfigurationProfile(BaseModel):
    """Represents an installed configuration profile on the device"""
    id: str
    name: str
    profile_type: str  # dns, vpn, mdm, certificate, wifi, email
    organization: Optional[str] = None
    description: Optional[str] = None
    installed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_removable: bool = True
    is_verified: bool = True  # Whether the profile is from a known/trusted source

class DNSConfiguration(BaseModel):
    """Represents the device's DNS configuration"""
    provider: str  # NextDNS, Cloudflare, Google, System Default, Custom
    servers: List[str] = []
    is_encrypted: bool = False  # DoH or DoT
    encryption_protocol: Optional[str] = None  # doh, dot, none
    is_filtering_enabled: bool = False
    is_logging_enabled: bool = False
    profile_id: Optional[str] = None  # Link to the profile that configured this

class Device(BaseModel):
    id: str
    device_name: str
    device_model: str
    ios_version: str
    last_seen_at: datetime
    status: str = "active"
    threat_count: int = 0
    # Extended properties for device detail view
    serial_number: Optional[str] = None
    udid: Optional[str] = None
    enrolled_at: Optional[datetime] = None
    storage_total_gb: Optional[float] = None
    storage_available_gb: Optional[float] = None
    battery_level: Optional[int] = None
    is_supervised: bool = False
    is_managed: bool = False
    vpn_connected: bool = False
    vpn_provider: Optional[str] = None
    carrier: Optional[str] = None
    wifi_mac: Optional[str] = None
    bluetooth_mac: Optional[str] = None
    imei: Optional[str] = None
    # Configuration profiles and DNS
    configuration_profiles: List[ConfigurationProfile] = []
    dns_config: Optional[DNSConfiguration] = None

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

class TelegramConfig(BaseModel):
    """Telegram notification configuration"""
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    notify_on_critical: bool = True
    notify_on_high: bool = True
    notify_on_medium: bool = False
    notify_on_low: bool = False

class BackupConfig(BaseModel):
    """Backup configuration"""
    enabled: bool = False
    location: str = "~/PrivaseeAI/backups"
    frequency: str = "daily"  # hourly, daily, weekly
    retention_days: int = 30
    include_logs: bool = True
    include_threats: bool = True
    encrypt_backups: bool = True
    last_backup: Optional[datetime] = None

class AlertThresholds(BaseModel):
    """Alert threshold configuration"""
    critical_threat_count: int = 1
    high_threat_count: int = 5
    medium_threat_count: int = 10
    device_offline_minutes: int = 30
    monitor_heartbeat_timeout_seconds: int = 120

class PrivaseeSettings(BaseModel):
    """Main application settings"""
    telegram: TelegramConfig = TelegramConfig()
    backup: BackupConfig = BackupConfig()
    thresholds: AlertThresholds = AlertThresholds()
    dark_mode: bool = False
    auto_refresh_interval: int = 30  # seconds
    demo_mode: bool = False  # Enable threat simulation

class ActivityLogEntry(BaseModel):
    """Activity log entry"""
    id: str
    timestamp: datetime
    action: str  # threat_detected, threat_resolved, monitor_started, etc.
    category: str  # threat, monitor, device, system, settings
    description: str
    details: Optional[Dict[str, Any]] = None
    user: str = "system"

# ============================================================================
# Mock Data (Phase 5A - Replace with database in Phase 5B)
# ============================================================================

# Application settings (persisted in memory for now)
app_settings = PrivaseeSettings()

# Activity log
activity_log: List[ActivityLogEntry] = []

def log_activity(action: str, category: str, description: str, details: Optional[Dict] = None):
    """Helper to add activity log entries"""
    entry = ActivityLogEntry(
        id=f"log-{len(activity_log)+1}",
        timestamp=datetime.now(),
        action=action,
        category=category,
        description=description,
        details=details
    )
    activity_log.insert(0, entry)  # Most recent first
    # Keep only last 1000 entries
    if len(activity_log) > 1000:
        activity_log.pop()

# Mock devices
mock_devices = [
    Device(
        id="device-1",
        device_name="Mark's iPhone",
        device_model="iPhone 16 Pro",
        ios_version="18.2",
        last_seen_at=datetime.now() - timedelta(minutes=2),
        status="active",
        threat_count=2,
        serial_number="F2LZK3XXXXXX",
        udid="00008110-001A2C3E4F5G6H78",
        enrolled_at=datetime.now() - timedelta(days=30),
        storage_total_gb=256.0,
        storage_available_gb=128.5,
        battery_level=87,
        is_supervised=True,
        is_managed=True,
        vpn_connected=True,
        vpn_provider="WireGuard",
        carrier="Verizon",
        wifi_mac="A4:83:E7:XX:XX:XX",
        bluetooth_mac="A4:83:E7:XX:XX:XY",
        imei="35XXXXXXXXXXXXXX",
        configuration_profiles=[
            ConfigurationProfile(
                id="profile-1",
                name="NextDNS Configuration",
                profile_type="dns",
                organization="NextDNS Inc.",
                description="Encrypted DNS with privacy filtering",
                installed_at=datetime.now() - timedelta(days=45),
                is_removable=True,
                is_verified=True
            ),
            ConfigurationProfile(
                id="profile-2",
                name="WireGuard VPN",
                profile_type="vpn",
                organization="WireGuard",
                description="Personal VPN configuration",
                installed_at=datetime.now() - timedelta(days=60),
                is_removable=True,
                is_verified=True
            ),
            ConfigurationProfile(
                id="profile-3",
                name="Corporate Root CA",
                profile_type="certificate",
                organization="PrivaseeAI Security",
                description="Root certificate for internal services",
                installed_at=datetime.now() - timedelta(days=30),
                expires_at=datetime.now() + timedelta(days=335),
                is_removable=False,
                is_verified=True
            ),
        ],
        dns_config=DNSConfiguration(
            provider="NextDNS",
            servers=["45.90.28.0", "45.90.30.0"],
            is_encrypted=True,
            encryption_protocol="doh",
            is_filtering_enabled=True,
            is_logging_enabled=True,
            profile_id="profile-1"
        )
    ),
    Device(
        id="device-2",
        device_name="Sarah's iPad",
        device_model="iPad Pro 12.9 (6th gen)",
        ios_version="17.4",
        last_seen_at=datetime.now() - timedelta(minutes=15),
        status="active",
        threat_count=0,
        serial_number="DLXQK4XXXXXX",
        udid="00008120-002B3D4E5F6G7H89",
        enrolled_at=datetime.now() - timedelta(days=60),
        storage_total_gb=512.0,
        storage_available_gb=312.8,
        battery_level=45,
        is_supervised=False,
        is_managed=True,
        vpn_connected=False,
        carrier=None,
        wifi_mac="B5:94:F8:XX:XX:XX",
        configuration_profiles=[
            ConfigurationProfile(
                id="profile-4",
                name="NextDNS Configuration",
                profile_type="dns",
                organization="NextDNS Inc.",
                description="Encrypted DNS with privacy filtering",
                installed_at=datetime.now() - timedelta(days=30),
                is_removable=True,
                is_verified=True
            ),
        ],
        dns_config=DNSConfiguration(
            provider="NextDNS",
            servers=["45.90.28.0", "45.90.30.0"],
            is_encrypted=True,
            encryption_protocol="doh",
            is_filtering_enabled=True,
            is_logging_enabled=False,
            profile_id="profile-4"
        )
    ),
    Device(
        id="device-3",
        device_name="Work iPhone",
        device_model="iPhone 15",
        ios_version="18.1",
        last_seen_at=datetime.now() - timedelta(hours=2),
        status="inactive",
        threat_count=1,
        serial_number="G3MNP5XXXXXX",
        udid="00008130-003C4E5F6G7H8I90",
        enrolled_at=datetime.now() - timedelta(days=90),
        storage_total_gb=128.0,
        storage_available_gb=23.4,
        battery_level=12,
        is_supervised=False,
        is_managed=False,
        vpn_connected=False,
        carrier="AT&T",
        wifi_mac="C6:A5:09:XX:XX:XX",
        configuration_profiles=[],
        dns_config=DNSConfiguration(
            provider="System Default",
            servers=[],
            is_encrypted=False,
            is_filtering_enabled=False,
            is_logging_enabled=False
        )
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
    Threat(
        id="threat-3",
        device_id="device-3",
        device_name="Work iPhone",
        threat_type="CERTIFICATE_ANOMALY",
        severity="LOW",
        title="Unknown certificate authority detected",
        description="A certificate signed by an unknown CA was encountered during a TLS connection.",
        detected_at=datetime.now() - timedelta(days=1),
        indicators=["UNKNOWN_CA", "TLS_WARNING"],
        status="open",
        occurrences=2
    ),
]

# Initialize activity log with some entries
activity_log.extend([
    ActivityLogEntry(
        id="log-init-1",
        timestamp=datetime.now() - timedelta(hours=2),
        action="threat_detected",
        category="threat",
        description="VPN manipulation detected on Mark's iPhone",
        details={"threat_id": "threat-1", "severity": "HIGH"}
    ),
    ActivityLogEntry(
        id="log-init-2",
        timestamp=datetime.now() - timedelta(hours=5),
        action="threat_detected",
        category="threat",
        description="Location API abuse detected on Mark's iPhone",
        details={"threat_id": "threat-2", "severity": "MEDIUM"}
    ),
    ActivityLogEntry(
        id="log-init-3",
        timestamp=datetime.now() - timedelta(minutes=30),
        action="monitor_started",
        category="monitor",
        description="VPNIntegrityMonitor started",
        details={"monitor_name": "VPNIntegrityMonitor"}
    ),
    ActivityLogEntry(
        id="log-init-4",
        timestamp=datetime.now() - timedelta(days=1),
        action="device_enrolled",
        category="device",
        description="Work iPhone enrolled in monitoring",
        details={"device_id": "device-3"}
    ),
])

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
# Settings API
# ============================================================================

@app.get("/api/settings", response_model=PrivaseeSettings)
async def get_settings():
    """Get current application settings"""
    return app_settings

@app.put("/api/settings")
async def update_settings(settings: PrivaseeSettings):
    """Update application settings"""
    global app_settings
    app_settings = settings
    log_activity("settings_updated", "settings", "Application settings updated")
    await manager.broadcast({
        "type": "settings_update",
        "timestamp": datetime.now().isoformat()
    })
    return {"success": True, "message": "Settings updated"}

@app.patch("/api/settings/telegram")
async def update_telegram_settings(config: TelegramConfig):
    """Update Telegram notification settings"""
    app_settings.telegram = config
    log_activity("telegram_updated", "settings", "Telegram settings updated",
                 {"enabled": config.enabled})
    return {"success": True, "message": "Telegram settings updated"}

@app.patch("/api/settings/backup")
async def update_backup_settings(config: BackupConfig):
    """Update backup settings"""
    app_settings.backup = config
    log_activity("backup_updated", "settings", "Backup settings updated",
                 {"location": config.location, "frequency": config.frequency})
    return {"success": True, "message": "Backup settings updated"}

@app.patch("/api/settings/thresholds")
async def update_threshold_settings(thresholds: AlertThresholds):
    """Update alert threshold settings"""
    app_settings.thresholds = thresholds
    log_activity("thresholds_updated", "settings", "Alert thresholds updated")
    return {"success": True, "message": "Threshold settings updated"}

@app.patch("/api/settings/dark-mode")
async def toggle_dark_mode(enabled: bool):
    """Toggle dark mode"""
    app_settings.dark_mode = enabled
    return {"success": True, "dark_mode": enabled}

# ============================================================================
# Activity Log API
# ============================================================================

@app.get("/api/activity", response_model=List[ActivityLogEntry])
async def get_activity_log(
    category: Optional[str] = Query(None),
    limit: int = Query(50, le=500)
):
    """Get activity log with optional filtering"""
    logs = activity_log
    if category:
        logs = [l for l in logs if l.category == category]
    return logs[:limit]

# ============================================================================
# Export API
# ============================================================================

@app.get("/api/export/threats")
async def export_threats(format: str = Query("json", regex="^(json|csv)$")):
    """Export threats data as JSON or CSV"""
    if format == "csv":
        # Generate CSV
        csv_lines = ["id,device_id,device_name,threat_type,severity,title,description,detected_at,status,occurrences"]
        for t in mock_threats:
            csv_lines.append(f'"{t.id}","{t.device_id}","{t.device_name}","{t.threat_type}","{t.severity}","{t.title}","{t.description}","{t.detected_at.isoformat()}","{t.status}",{t.occurrences}')
        content = "\n".join(csv_lines)
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threats_export.csv"}
        )
    else:
        # JSON format
        data = [t.model_dump() for t in mock_threats]
        for item in data:
            item["detected_at"] = item["detected_at"].isoformat()
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threats_export.json"}
        )

@app.get("/api/export/devices")
async def export_devices(format: str = Query("json", regex="^(json|csv)$")):
    """Export devices data as JSON or CSV"""
    if format == "csv":
        csv_lines = ["id,device_name,device_model,ios_version,status,threat_count,last_seen_at"]
        for d in mock_devices:
            csv_lines.append(f'"{d.id}","{d.device_name}","{d.device_model}","{d.ios_version}","{d.status}",{d.threat_count},"{d.last_seen_at.isoformat()}"')
        content = "\n".join(csv_lines)
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices_export.csv"}
        )
    else:
        data = []
        for d in mock_devices:
            device_dict = d.model_dump()
            device_dict["last_seen_at"] = device_dict["last_seen_at"].isoformat()
            if device_dict.get("enrolled_at"):
                device_dict["enrolled_at"] = device_dict["enrolled_at"].isoformat()
            data.append(device_dict)
        return StreamingResponse(
            iter([json.dumps(data, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=devices_export.json"}
        )

# ============================================================================
# Threat Simulation (Demo Mode)
# ============================================================================

simulation_running = False

@app.post("/api/simulate/start")
async def start_simulation():
    """Start threat simulation demo mode"""
    global simulation_running
    app_settings.demo_mode = True
    simulation_running = True
    log_activity("simulation_started", "system", "Threat simulation demo mode started")
    return {"success": True, "message": "Simulation started"}

@app.post("/api/simulate/stop")
async def stop_simulation():
    """Stop threat simulation demo mode"""
    global simulation_running
    app_settings.demo_mode = False
    simulation_running = False
    log_activity("simulation_stopped", "system", "Threat simulation demo mode stopped")
    return {"success": True, "message": "Simulation stopped"}

@app.post("/api/simulate/threat")
async def simulate_threat():
    """Generate a simulated threat"""
    threat_templates = [
        ("CRITICAL", "CARRIER_COMPROMISE", "SIM swap attack detected", "Unusual SIM activity detected. Your carrier may have been compromised."),
        ("HIGH", "VPN_MANIPULATION", "VPN tunnel disrupted", "Network conditions are forcing VPN protocol changes."),
        ("HIGH", "CERTIFICATE_PINNING", "Certificate pinning bypassed", "An app's certificate pinning was bypassed, indicating possible MITM attack."),
        ("MEDIUM", "DNS_HIJACKING", "DNS queries redirected", "DNS resolution is being redirected to unknown servers."),
        ("MEDIUM", "API_ABUSE", "Suspicious API access pattern", "Unusual frequency of sensitive API calls detected."),
        ("LOW", "LOCATION_TRACKING", "Location access anomaly", "Background location access from unusual source detected."),
    ]

    template = random.choice(threat_templates)
    device = random.choice(mock_devices)

    new_threat = Threat(
        id=f"threat-sim-{len(mock_threats)+1}",
        device_id=device.id,
        device_name=device.device_name,
        threat_type=template[1],
        severity=template[0],
        title=template[2],
        description=template[3],
        detected_at=datetime.now(),
        indicators=[template[1], f"SIMULATED"],
        status="open",
        occurrences=1
    )

    mock_threats.insert(0, new_threat)
    device.threat_count += 1

    log_activity("threat_detected", "threat", f"Simulated: {new_threat.title}",
                 {"threat_id": new_threat.id, "severity": new_threat.severity})

    await manager.broadcast({
        "type": "threat_new",
        "threat": {
            "id": new_threat.id,
            "severity": new_threat.severity,
            "title": new_threat.title
        },
        "timestamp": datetime.now().isoformat()
    })

    return {"success": True, "threat": new_threat.model_dump()}

# ============================================================================
# Bulk Operations
# ============================================================================

@app.post("/api/threats/bulk/resolve")
async def bulk_resolve_threats(threat_ids: List[str]):
    """Resolve multiple threats at once"""
    resolved = []
    for threat_id in threat_ids:
        threat = next((t for t in mock_threats if t.id == threat_id), None)
        if threat:
            threat.status = "resolved"
            resolved.append(threat_id)

    if resolved:
        log_activity("threats_bulk_resolved", "threat",
                     f"Bulk resolved {len(resolved)} threats",
                     {"threat_ids": resolved})
        await manager.broadcast({
            "type": "threats_bulk_update",
            "resolved": resolved,
            "timestamp": datetime.now().isoformat()
        })

    return {"success": True, "resolved": resolved}

@app.post("/api/threats/resolve-all")
async def resolve_all_threats():
    """Resolve all open threats"""
    resolved = []
    for threat in mock_threats:
        if threat.status == "open":
            threat.status = "resolved"
            resolved.append(threat.id)

    # Update device threat counts
    for device in mock_devices:
        device.threat_count = len([t for t in mock_threats
                                   if t.device_id == device.id and t.status == "open"])

    log_activity("threats_all_resolved", "threat",
                 f"All threats resolved ({len(resolved)} total)",
                 {"count": len(resolved)})

    await manager.broadcast({
        "type": "threats_all_resolved",
        "count": len(resolved),
        "timestamp": datetime.now().isoformat()
    })

    return {"success": True, "resolved_count": len(resolved)}

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
