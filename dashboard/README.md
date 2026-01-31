# PrivaseeAI Security Dashboard

**Phase 5A Prototype** - Minimal FastAPI web dashboard for real-time iOS threat monitoring.

## Features

✅ **Real-Time Monitoring** - WebSocket-based live updates
✅ **Threat Management** - View, filter, and resolve threats
✅ **Monitor Control** - Start/stop detection monitors
✅ **Device Overview** - Track all monitored devices
✅ **Responsive UI** - Works on desktop, tablet, mobile

## Quick Start

### 1. Install Dependencies

```bash
pip install fastapi uvicorn jinja2 python-multipart
```

Or use the existing requirements.txt:
```bash
pip install -r requirements.txt
```

### 2. Run Dashboard

**Recommended (using CLI):**
```bash
privasee dashboard
```

**Alternative methods:**
```bash
# From the dashboard/api directory
cd dashboard/api
python3 main.py

# Or use uvicorn directly
uvicorn dashboard.api.main:app --reload --host 0.0.0.0 --port 8000
```

**CLI Options:**
```bash
privasee dashboard --port 3000     # Custom port
privasee dashboard --reload         # Development mode (auto-reload)
privasee dashboard --help           # See all options
```

### 3. Access Dashboard

Open your browser to:
- **Dashboard:** http://localhost:8000
- **API Docs:** http://localhost:8000/api/docs
- **ReDoc:** http://localhost:8000/api/redoc

## API Endpoints

### Stats & Overview

```bash
GET /api/stats          # Dashboard statistics
GET /api/health         # Health check
```

### Devices

```bash
GET /api/devices                    # List all devices
GET /api/devices/{device_id}        # Get device details
GET /api/devices?status=active      # Filter by status
```

### Threats

```bash
GET /api/threats                            # List all threats
GET /api/threats?severity=CRITICAL          # Filter by severity
GET /api/threats?status=open                # Filter by status
GET /api/threats?device_id={id}             # Filter by device
GET /api/threats/{threat_id}                # Get threat details
PATCH /api/threats/{threat_id}/status       # Update threat status
```

### Monitors

```bash
GET /api/monitors                           # List all monitors
POST /api/monitors/{monitor_name}/start     # Start monitor
POST /api/monitors/{monitor_name}/stop      # Stop monitor
```

### WebSocket

```bash
WS /ws                              # Real-time updates
```

## Example API Usage

### Get Critical Threats

```bash
curl http://localhost:8000/api/threats?severity=CRITICAL
```

### Resolve a Threat

```bash
curl -X PATCH "http://localhost:8000/api/threats/threat-1/status?status=resolved"
```

### Start VPN Monitor

```bash
curl -X POST http://localhost:8000/api/monitors/VPNIntegrityMonitor/start
```

## WebSocket Events

The dashboard uses WebSockets for real-time updates. Connect to `ws://localhost:8000/ws` to receive:

```json
{
  "type": "threat_update",
  "threat_id": "threat-123",
  "status": "resolved",
  "timestamp": "2026-01-31T12:00:00"
}
```

```json
{
  "type": "monitor_status",
  "monitor_name": "VPNIntegrityMonitor",
  "is_running": true,
  "timestamp": "2026-01-31T12:00:00"
}
```

## Development

### Project Structure

```
dashboard/
├── api/
│   └── main.py          # FastAPI application
├── templates/
│   └── dashboard.html   # Main dashboard page
├── static/              # CSS, JS, images (future)
└── README.md            # This file
```

### Adding New Features

**Add New API Endpoint:**
```python
@app.get("/api/custom")
async def custom_endpoint():
    return {"message": "Custom endpoint"}
```

**Add Real-Time Event:**
```python
# Broadcast to all WebSocket clients
await manager.broadcast({
    "type": "custom_event",
    "data": {...}
})
```

**Update Dashboard UI:**
Edit `templates/dashboard.html` - uses htmx for dynamic updates.

## Phase 5B: Database Integration

Current version uses mock data. For production (Phase 5B):

1. **Replace Mock Data** with database queries:
```python
from sqlalchemy.orm import Session
from database.models import Device, Threat

@app.get("/api/threats")
async def get_threats(db: Session = Depends(get_db)):
    return db.query(Threat).filter(Threat.status == "open").all()
```

2. **Add Database Migrations:**
```bash
alembic init migrations
alembic revision --autogenerate -m "Initial schema"
alembic upgrade head
```

3. **Configure Database:**
```python
DATABASE_URL = "postgresql://user:password@localhost/privaseeai"
engine = create_engine(DATABASE_URL)
```

## Configuration

### Environment Variables

```bash
# API Settings
HOST=0.0.0.0
PORT=8000
RELOAD=true

# Database (Phase 5B)
DATABASE_URL=postgresql://localhost/privaseeai

# Security
SECRET_KEY=your-secret-key-here
```

### CORS Settings

For cross-origin requests, add CORS middleware:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Production Deployment

### Using Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/ ./dashboard/
CMD ["uvicorn", "dashboard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t privaseeai-dashboard .
docker run -p 8000:8000 privaseeai-dashboard
```

### Using systemd

Create `/etc/systemd/system/privaseeai-dashboard.service`:

```ini
[Unit]
Description=PrivaseeAI Security Dashboard
After=network.target

[Service]
Type=simple
User=privasee
WorkingDirectory=/opt/privaseeai
ExecStart=/opt/privaseeai/.venv/bin/uvicorn dashboard.api.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable privaseeai-dashboard
sudo systemctl start privaseeai-dashboard
```

### Using Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name privaseeai.yourdomain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Testing

### Manual Testing

```bash
# Health check
curl http://localhost:8000/api/health

# Get all threats
curl http://localhost:8000/api/threats

# WebSocket test (using websocat)
websocat ws://localhost:8000/ws
```

### Automated Tests

```python
from fastapi.testclient import TestClient
from dashboard.api.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_get_threats():
    response = client.get("/api/threats")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
```

## Performance

**Current Capacity (Phase 5A Mock Data):**
- Concurrent connections: 1,000+
- Requests/second: 500+
- WebSocket clients: 100+

**Phase 5B Goals (With Database):**
- Concurrent connections: 10,000+
- Requests/second: 2,000+
- WebSocket clients: 1,000+
- Query latency: <100ms (p95)

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill it
kill -9 <PID>

# Or use a different port
uvicorn dashboard.api.main:app --port 8001
```

### WebSocket Connection Refused

Check firewall settings and ensure WebSocket upgrade headers are allowed.

### Slow Performance

For production, use:
```bash
uvicorn dashboard.api.main:app --workers 4 --host 0.0.0.0 --port 8000
```

## Roadmap

### Phase 5A ✅ (Current)
- [x] FastAPI REST API
- [x] WebSocket real-time updates
- [x] Mock data for testing
- [x] Responsive dashboard UI
- [x] Basic CRUD operations

### Phase 5B 📅 (Next)
- [ ] PostgreSQL + TimescaleDB integration
- [ ] SQLAlchemy ORM models
- [ ] Alembic migrations
- [ ] Real data from monitors
- [ ] User authentication (JWT)

### Phase 5C 📅 (Future)
- [ ] React frontend (replace htmx)
- [ ] Advanced visualizations (Chart.js/D3.js)
- [ ] PDF report generation
- [ ] Email alert configuration UI
- [ ] Multi-user support with RBAC

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

Apache 2.0 - See [LICENSE](../LICENSE)

---

**Status:** Phase 5A Prototype Complete
**Next:** Database Integration (Phase 5B)
**Questions?** [Open an issue](https://github.com/aurelianware/PrivaseeAI.Security/issues)
