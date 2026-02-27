# Auraveil — Implementation Guide

Complete technical implementation reference for the Phase 1 MVP build.

---

## 1. Project Structure

```
Auraveil/
├── backend/
│   ├── monitoring/
│   │   ├── __init__.py
│   │   ├── system_monitor.py        # Process & resource metrics
│   │   ├── file_monitor.py          # File system event tracking
│   │   └── network_monitor.py       # Packet capture & connection tracking (Scapy)
│   ├── ai_engine/
│   │   ├── __init__.py
│   │   ├── anomaly_detector.py      # Isolation Forest model
│   │   └── feature_engineering.py   # Feature extraction & normalization
│   ├── database/
│   │   ├── __init__.py
│   │   └── models.py               # SQLite schema & helpers
│   ├── api/
│   │   ├── __init__.py
│   │   └── main.py                 # FastAPI app, REST + WebSocket
│   ├── __init__.py
│   ├── requirements.txt
│   └── config.py                   # Global configuration
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── MetricsChart.tsx     # CPU/Memory area charts
│   │   │   ├── ProcessList.tsx      # Process table with threat scores
│   │   │   ├── AlertFeed.tsx        # Live alert feed
│   │   │   ├── ThreatTimeline.tsx   # Historical threat timeline
│   │   │   └── StatusBar.tsx        # Connection & system summary
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts      # WebSocket with auto-reconnect
│   │   │   └── useMetrics.ts        # Metrics state management
│   │   ├── stores/
│   │   │   └── threatStore.ts       # Zustand state store
│   │   ├── types/
│   │   │   └── index.ts             # Shared TypeScript interfaces
│   │   ├── App.tsx
│   │   ├── App.css
│   │   └── main.tsx
│   ├── package.json
│   └── index.html
├── data/
│   └── auraveil.db                  # SQLite database (auto-created)
├── models/
│   └── baseline_model.pkl           # Trained Isolation Forest (auto-created)
├── Plan.md
├── Implementation.md
└── README.md
```

---

## 2. Technology Stack

### Backend

| Layer             | Technology                  | Version   | Purpose                                  |
|-------------------|-----------------------------|-----------|------------------------------------------|
| **API Server**    | FastAPI                     | ≥0.110    | REST endpoints + WebSocket               |
| **ASGI Runtime**  | Uvicorn                     | ≥0.27     | Production-grade async server            |
| **Monitoring**    | psutil                      | ≥5.9      | CPU, memory, disk, network per process   |
| **File Events**   | watchdog                    | ≥4.0      | Real-time file create/modify/delete      |
| **Network**       | Scapy                       | ≥2.5      | Packet capture, protocol analysis, connection tracking |
| **Network Driver**| Npcap                       | Latest    | Windows packet capture driver (required by Scapy) |
| **ML Framework**  | scikit-learn                | ≥1.4      | Isolation Forest anomaly detection       |
| **Numerics**      | numpy                       | ≥1.26     | Feature vector operations                |
| **Data**          | pandas                      | ≥2.2      | Baseline analysis & data manipulation    |
| **Database**      | SQLite3                     | Built-in  | Threat logs, whitelists, baselines       |
| **Serialization** | msgpack                     | ≥1.0      | Fast binary serialization for buffers    |
| **Async**         | asyncio                     | Built-in  | Background monitoring tasks              |
| **Buffering**     | collections.deque           | Built-in  | In-memory rolling window (30 min)        |

### Frontend

| Layer               | Technology     | Purpose                         |
|---------------------|----------------|----------------------------------|
| **Build Tool**      | Vite           | Fast dev server + bundler        |
| **UI Framework**    | React 18       | Component-based dashboard        |
| **Language**        | TypeScript     | Type safety                      |
| **Styling**         | TailwindCSS    | Utility-first CSS                |
| **Charts**          | Recharts       | Real-time CPU/memory graphs      |
| **State**           | Zustand        | Lightweight reactive state       |
| **HTTP Client**     | Axios          | REST API calls                   |
| **Real-time**       | WebSocket API  | Live metrics streaming           |

### Testing

| Tool            | Purpose                    |
|-----------------|----------------------------|
| pytest          | Backend unit tests          |
| pytest-asyncio  | Async endpoint testing      |
| pytest-cov      | Code coverage               |
| Jest            | Frontend component tests    |
| Playwright      | End-to-end browser testing  |

---

## 3. Data Flow Architecture

```
┌─────────────────────┐
│   System (OS)       │
│  Processes, Files,  │
│  Network, Disk      │
└────────┬────────────┘
         │ psutil + watchdog + scapy (1s polling + event-driven)
         ▼
┌─────────────────────┐
│  Monitoring Layer   │
│  SystemMonitor      │     Collects raw metrics per process
│  FileActivityMonitor│     Tracks file system events
│  NetworkMonitor     │     Packet capture & connection tracking (Scapy + Npcap)
└────────┬────────────┘
         │ Raw metrics dict
         ▼
┌─────────────────────┐
│  In-Memory Buffer   │
│  collections.deque  │     Rolling 30-min window (1800 entries)
└────────┬────────────┘
         │ Feature vectors (numpy arrays)
         ▼
┌─────────────────────┐
│  AI Engine          │
│  IsolationForest    │     Anomaly detection → threat score 0–100
│  FeatureEngineering │     Normalization, windowing, rate-of-change
└────────┬────────────┘
         │ Threat score + reason codes
         ▼
┌─────────────────────┐
│  Threat Scoring     │
│  Classification:    │     Safe (0–30) / Suspicious (31–70) / Malicious (71–100)
│  + Reason Codes     │     "High CPU spike", "Rapid file writes", etc.
└────────┬────────────┘
         │ Alerts + scored metrics
         ▼
┌────────┴────────────┐
│  Response Layer     │     Log to SQLite, trigger alerts,
│  + SQLite Storage   │     auto-stop if malicious + user config allows
└────────┬────────────┘
         │ JSON via REST + WebSocket
         ▼
┌─────────────────────┐
│  FastAPI Server     │
│  REST: /api/*       │     History, whitelist, config
│  WS:   /ws/live     │     Real-time metrics stream (1s)
└────────┬────────────┘
         │ HTTP / WebSocket
         ▼
┌─────────────────────┐
│  React Dashboard    │
│  Charts, Tables,    │     Live process list, alert feed,
│  Alert Feed         │     threat timeline, manual controls
└─────────────────────┘
```

---

## 4. Module Specifications

### 4.1 Monitoring Layer

#### `SystemMonitor` — `backend/monitoring/system_monitor.py`

```python
class SystemMonitor:
    """Collects real-time system and per-process metrics."""

    def __init__(self, buffer_size: int = 1800):
        self.buffer = deque(maxlen=buffer_size)  # 30 min at 1s interval

    def collect_metrics(self) -> dict:
        """
        Returns:
            {
                "timestamp": "ISO-8601",
                "system": {
                    "cpu_percent": float,
                    "memory_percent": float,
                    "disk_io": {"read_bytes": int, "write_bytes": int, ...},
                    "net_io": {"bytes_sent": int, "bytes_recv": int, ...}
                },
                "processes": [
                    {
                        "pid": int,
                        "name": str,
                        "cpu_percent": float,
                        "memory_percent": float,
                        "num_threads": int,
                        "io_counters": {"read_bytes": int, "write_bytes": int, ...}
                    }, ...
                ]
            }
        """
```

**Design decisions:**
- Uses `psutil.process_iter()` with attrs filter for performance
- Silently skips processes that disappear or deny access (`NoSuchProcess`, `AccessDenied`)
- Appends each snapshot to the deque buffer automatically
- Target overhead: **<5% CPU** on consumer hardware

#### `FileActivityMonitor` — `backend/monitoring/file_monitor.py`

```python
class FileActivityMonitor:
    """Tracks file system events using watchdog."""

    def __init__(self, watch_paths: list[str]):
        self.event_counts = defaultdict(lambda: {"created": 0, "modified": 0, "deleted": 0})

    def get_activity_summary(self) -> dict:
        """Returns file event rates since last call."""

    def start(self):
        """Start watching configured paths."""

    def stop(self):
        """Stop file system observer."""
```

**Design decisions:**
- Watches user-sensitive directories (Documents, Desktop, Downloads) by default
- Rapid file modification bursts are a key ransomware signal
- Event counts are aggregated per-second to match the monitoring interval

#### `NetworkMonitor` — `backend/monitoring/network_monitor.py`

> **Prerequisite:** [Npcap](https://npcap.com/#download) must be installed on Windows for Scapy packet capture to work. Install with "WinPcap API-compatible mode" enabled.

```python
class NetworkMonitor:
    """Packet-level network monitoring using Scapy + Npcap."""

    def __init__(self, interface: str = None):
        self.connections = {}          # Active connections by (src, dst, port)
        self.packet_buffer = deque(maxlen=1000)
        self.stats = {
            "packets_in": 0,
            "packets_out": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "unique_destinations": set(),
            "dns_queries": [],
            "suspicious_ports": [],
        }

    def start_capture(self):
        """Start async packet sniffing on the selected interface."""

    def stop_capture(self):
        """Stop packet capture."""

    def _process_packet(self, packet):
        """
        Callback for each captured packet.
        - Track connections (TCP SYN/FIN/RST)
        - Count bytes per destination
        - Log DNS queries
        - Flag known-suspicious ports (4444, 5555, etc.)
        """

    def get_network_summary(self) -> dict:
        """
        Returns:
            {
                "packets_in": int,
                "packets_out": int,
                "bytes_in": int,
                "bytes_out": int,
                "active_connections": int,
                "unique_destinations": int,
                "dns_queries": ["example.com", ...],
                "suspicious_ports": [4444, ...]
            }
        """

    def get_per_process_network(self) -> dict:
        """
        Cross-reference Scapy connections with psutil.net_connections()
        to attribute network activity to specific processes.
        Returns: {pid: {"bytes_sent": int, "bytes_recv": int, "connections": int}}
        """
```

**Design decisions:**
- Runs packet capture in a background thread to avoid blocking the monitor loop
- Uses `scapy.sniff()` with a BPF filter to reduce overhead (e.g., `tcp or udp or dns`)
- Cross-references captured packets with `psutil.net_connections()` to map traffic → PID
- Flags connections to known C2 ports, high volumes of outbound traffic, and unusual DNS queries
- Gracefully degrades if Npcap is not installed (falls back to `psutil.net_io_counters()` only)

---

### 4.2 AI Engine

#### `AnomalyDetector` — `backend/ai_engine/anomaly_detector.py`

```python
class AnomalyDetector:
    """Isolation Forest-based anomaly detection for process behavior."""

    def __init__(self, contamination: float = 0.01):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,  # Expect 1% anomalies
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def prepare_features(self, process_data: dict) -> np.ndarray:
        """
        Extract feature vector from a single process snapshot.

        Features (v1):
            [cpu_percent, memory_percent, num_threads,
             read_bytes, write_bytes, read_count, write_count]
        """

    def train(self, historical_data: list[dict]):
        """Fit model on baseline data (7+ days recommended)."""

    def predict(self, process_data: dict) -> tuple[int, list[str]]:
        """
        Returns:
            threat_score: int (0–100, higher = more anomalous)
            reasons: list[str] (e.g., ["High CPU spike", "Unusual disk writes"])
        """

    def save_model(self, path: str):
        """Persist trained model to disk via pickle."""

    def load_model(self, path: str):
        """Load pre-trained model from disk."""
```

**Threat score mapping:**
| Score Range | Classification | Action                    |
|-------------|---------------|---------------------------|
| 0–30        | Safe          | No action                 |
| 31–70       | Suspicious    | Alert user                |
| 71–100      | Malicious     | Alert + auto-stop (if configured) |

**Reason code generation:**
- Compare each feature value to baseline mean ± 2σ
- If a feature exceeds threshold, add a human-readable reason
- Examples: `"CPU usage 4.2x above normal"`, `"Disk write rate 10x spike"`

#### `FeatureEngineering` — `backend/ai_engine/feature_engineering.py`

```python
class FeatureEngineering:
    """Transforms raw metrics into ML-ready feature vectors."""

    def compute_rate_of_change(self, current: dict, previous: dict) -> dict:
        """Delta between consecutive snapshots."""

    def compute_rolling_stats(self, buffer: deque, window: int = 60) -> dict:
        """Mean, std, max over a sliding window."""

    def normalize(self, features: np.ndarray) -> np.ndarray:
        """StandardScaler normalization."""
```

---

### 4.3 Database Layer

#### `models.py` — `backend/database/models.py`

**Schema:**

```sql
CREATE TABLE IF NOT EXISTS threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    process_name TEXT NOT NULL,
    pid         INTEGER,
    threat_score INTEGER CHECK(threat_score BETWEEN 0 AND 100),
    risk_level  TEXT CHECK(risk_level IN ('safe', 'suspicious', 'malicious')),
    reasons     TEXT,       -- JSON array: ["High CPU spike", "Rapid disk writes"]
    action_taken TEXT,      -- "alerted", "auto_stopped", "whitelisted", "ignored"
    resolved    BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS whitelist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name TEXT UNIQUE NOT NULL,
    hash        TEXT,       -- SHA-256 of executable (future)
    added_at    TEXT NOT NULL,
    reason      TEXT
);

CREATE TABLE IF NOT EXISTS system_baseline (
    metric_name TEXT PRIMARY KEY,
    mean_value  REAL,
    std_value   REAL,
    min_value   REAL,
    max_value   REAL,
    sample_count INTEGER,
    last_updated TEXT
);

CREATE INDEX idx_threats_timestamp ON threats(timestamp);
CREATE INDEX idx_threats_risk ON threats(risk_level);
```

**Helper functions:**

```python
def init_db(db_path: str = "data/auraveil.db"):
    """Create tables if they don't exist."""

def log_threat(process_name: str, pid: int, score: int, level: str, reasons: list, action: str):
    """Insert a threat record."""

def get_threat_history(days: int = 7, risk_level: str = None) -> list[dict]:
    """Query threat history with optional filters."""

def add_to_whitelist(process_name: str, reason: str = "User approved"):
    """Whitelist a process to suppress future alerts."""

def is_whitelisted(process_name: str) -> bool:
    """Check if a process is on the whitelist."""

def update_baseline(metric_name: str, mean: float, std: float):
    """Update or insert baseline statistics."""
```

---

### 4.4 Backend API

#### `main.py` — `backend/api/main.py`

**REST Endpoints:**

| Method | Path                        | Purpose                             |
|--------|-----------------------------|-------------------------------------|
| GET    | `/api/metrics/current`      | Current system + process metrics    |
| GET    | `/api/threats/history`      | Threat history (query: `days`, `risk_level`) |
| GET    | `/api/threats/active`       | Unresolved threats                  |
| POST   | `/api/threats/{id}/resolve` | Mark threat as resolved             |
| GET    | `/api/whitelist`            | List all whitelisted processes      |
| POST   | `/api/whitelist/{name}`     | Add process to whitelist            |
| DELETE | `/api/whitelist/{name}`     | Remove process from whitelist       |
| GET    | `/api/status`               | Engine status (trained, uptime, etc.) |

**WebSocket:**

| Path        | Purpose                                          |
|-------------|--------------------------------------------------|
| `/ws/live`  | Streams enriched metrics (with threat scores) every 1s |

**WebSocket message format:**
```json
{
  "timestamp": "2026-02-24T13:45:00",
  "system": {
    "cpu_percent": 23.5,
    "memory_percent": 61.2,
    "disk_io": {"read_bytes": 1048576, "write_bytes": 524288},
    "net_io": {"bytes_sent": 2048, "bytes_recv": 8192}
  },
  "network": {
    "packets_in": 342,
    "packets_out": 198,
    "bytes_in": 524288,
    "bytes_out": 131072,
    "active_connections": 14,
    "unique_destinations": 8,
    "dns_queries": ["cdn.example.com"],
    "suspicious_ports": []
  },
  "processes": [
    {
      "pid": 1234,
      "name": "chrome.exe",
      "cpu_percent": 12.3,
      "memory_percent": 8.5,
      "num_threads": 42,
      "threat_score": 15,
      "risk_level": "safe",
      "reasons": []
    },
    {
      "pid": 5678,
      "name": "suspicious.exe",
      "cpu_percent": 95.0,
      "memory_percent": 45.2,
      "num_threads": 3,
      "threat_score": 82,
      "risk_level": "malicious",
      "reasons": ["CPU usage 8x above normal", "Rapid file writes detected", "Connection to suspicious port 4444"]
    }
  ],
  "active_alerts": 2
}
```

**Background tasks:**
- `continuous_monitoring()` — Runs every 1s, collects metrics, runs anomaly detection, logs threats above threshold
- `baseline_trainer()` — Periodically retrains the model on accumulated normal data

---

### 4.5 Frontend Dashboard

#### TypeScript Interfaces — `frontend/src/types/index.ts`

```typescript
export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  disk_io: { read_bytes: number; write_bytes: number };
  net_io: { bytes_sent: number; bytes_recv: number };
}

export interface NetworkMetrics {
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
  active_connections: number;
  unique_destinations: number;
  dns_queries: string[];
  suspicious_ports: number[];
}

export interface ProcessInfo {
  pid: number;
  name: string;
  cpu_percent: number;
  memory_percent: number;
  num_threads: number;
  threat_score: number;
  risk_level: 'safe' | 'suspicious' | 'malicious';
  reasons: string[];
}

export interface MetricsSnapshot {
  timestamp: string;
  system: SystemMetrics;
  network: NetworkMetrics;
  processes: ProcessInfo[];
  active_alerts: number;
}

export interface ThreatRecord {
  id: number;
  timestamp: string;
  process_name: string;
  pid: number;
  threat_score: number;
  risk_level: string;
  reasons: string[];
  action_taken: string;
  resolved: boolean;
}
```

#### Component Responsibilities

| Component          | Data Source     | Renders                                       |
|--------------------|---------------|------------------------------------------------|
| `MetricsChart`     | WebSocket      | CPU & memory area charts (last 60 data points) |
| `ProcessList`      | WebSocket      | Sortable table — name, CPU, memory, threat score, risk badge |
| `AlertFeed`        | WebSocket + REST | Live alerts with reason explanations          |
| `ThreatTimeline`   | REST           | Historical threat chart (last 24h/7d)          |
| `StatusBar`        | WebSocket      | Connection status, uptime, total processes, active alerts |

#### Zustand Store — `frontend/src/stores/threatStore.ts`

```typescript
interface ThreatStore {
  // State
  latestSnapshot: MetricsSnapshot | null;
  metricsHistory: SystemMetrics[];    // Last 60 snapshots for charts
  activeAlerts: ThreatRecord[];
  connected: boolean;

  // Actions
  updateSnapshot: (snapshot: MetricsSnapshot) => void;
  setConnected: (status: boolean) => void;
  addAlert: (alert: ThreatRecord) => void;
  resolveAlert: (id: number) => void;
}
```

#### Dashboard Layout

```
┌─────────────────────────────────────────────────────────┐
│  StatusBar — Connection ● | Uptime: 2h 15m | Procs: 142 │
├───────────────────────────┬─────────────────────────────┤
│                           │                             │
│   MetricsChart            │   AlertFeed                 │
│   CPU ████████░░ 45%      │   ⚠ suspicious.exe (72)    │
│   RAM ██████░░░░ 61%      │   🔴 malware.exe (95)      │
│                           │   ⚠ unknown.exe (58)       │
│                           │                             │
├───────────────────────────┴─────────────────────────────┤
│                                                         │
│   ProcessList                                           │
│   ┌──────────────────────────────────────────────────┐  │
│   │ Name          │ CPU  │ Memory │ Score │ Risk     │  │
│   │ chrome.exe    │ 12%  │  8.5%  │  15   │ 🟢 Safe │  │
│   │ vscode.exe    │  8%  │  6.2%  │  10   │ 🟢 Safe │  │
│   │ suspicious.exe│ 95%  │ 45.2%  │  82   │ 🔴 Mal  │  │
│   └──────────────────────────────────────────────────┘  │
│                                                         │
├─────────────────────────────────────────────────────────┤
│   ThreatTimeline — Historical threats (7-day view)      │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Configuration

#### `backend/config.py`

```python
# Monitoring
MONITOR_INTERVAL_SECONDS = 1        # Polling frequency
BUFFER_SIZE = 1800                  # 30 minutes of data at 1s intervals

# AI Engine
CONTAMINATION_RATE = 0.01           # Expected % of anomalous behavior
MIN_TRAINING_SAMPLES = 3600         # 1 hour of data before model trains
RETRAIN_INTERVAL_HOURS = 24         # How often to retrain baseline model

# Threat Thresholds
THRESHOLD_SAFE = 30                 # Score 0–30
THRESHOLD_SUSPICIOUS = 70           # Score 31–70
# Score 71–100 = Malicious

# Response
AUTO_STOP_ENABLED = False           # Disabled by default (safety-first)
AUTO_STOP_THRESHOLD = 90            # Only auto-stop above this score

# Database
DB_PATH = "data/auraveil.db"

# API
API_HOST = "127.0.0.1"
API_PORT = 8000
CORS_ORIGINS = ["http://localhost:5173"]  # Vite dev server

# File Monitoring
WATCHED_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# Network Monitoring (Scapy + Npcap)
NETWORK_INTERFACE = None             # None = auto-detect default interface
PACKET_BUFFER_SIZE = 1000            # Max packets in memory
BPF_FILTER = "tcp or udp"           # Scapy BPF filter to reduce overhead
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337]  # Known C2/backdoor ports
NPCAP_FALLBACK = True                # Fall back to psutil if Npcap unavailable
```

---

## 6. Setup & Run Instructions

### Backend

```bash
# 0. Install Npcap (required for Scapy on Windows)
#    Download from https://npcap.com/#download
#    During install, check: "Install in WinPcap API-compatible mode"

# 1. Create virtual environment
cd d:\Projects\Auraveil\backend
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize database
python -c "from database.models import init_db; init_db()"

# 4. Start the server (run as Administrator for Scapy packet capture)
uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend

```bash
# 1. Create Vite React project (first time only)
cd d:\Projects\Auraveil\frontend
npm install

# 2. Start dev server
npm run dev
# Opens at http://localhost:5173
```

### Both (development)

Run backend and frontend in separate terminals. The dashboard at `localhost:5173` connects to the API at `localhost:8000` via HTTP and WebSocket.

---

## 7. Development Phases

### Phase 1 — MVP (Weeks 1–3)

| Week | Deliverable                                    |
|------|------------------------------------------------|
| 1    | Monitoring Layer + SQLite schema + basic API    |
| 2    | Isolation Forest anomaly detection + scoring    |
| 3    | React dashboard + WebSocket integration + alerts |

**MVP success criteria:**
- Detects abnormal process behavior without signatures
- Stops a simulated ransomware attack (rapid file encryption)
- Runs with <5% CPU overhead
- Provides clear, jargon-free alerts
- Operates fully offline

### Phase 2 — Advanced Features (Post-MVP)

| Feature                    | Technology                    |
|----------------------------|-------------------------------|
| Deep learning models       | PyTorch (LSTM, Transformers)  |
| Graph-based analysis       | PyTorch Geometric (GNN)       |
| Model explainability       | SHAP                          |
| AMD hardware telemetry     | linux-perf, pyRAPL, ROCm      |
| High-perf caching          | Redis                         |
| Cross-platform (macOS)     | Platform-specific adaptors    |

---

## 8. Security Considerations

| Concern                          | Mitigation                                          |
|----------------------------------|-----------------------------------------------------|
| Auraveil itself targeted         | Run as a Windows Service with restricted permissions |
| False positives disrupting user  | Auto-stop disabled by default; user must opt-in      |
| Model poisoning via long run     | Periodic retrain with outlier filtering              |
| SQLite injection                 | Parameterized queries only                          |
| WebSocket hijacking              | Bind to `127.0.0.1` only; no external access        |
| Sensitive process names leaked   | All data stays on-device; no telemetry               |

---

## 9. Testing Strategy

```bash
# Backend unit tests
cd backend
pytest tests/ -v --cov=. --cov-report=term-missing

# Frontend tests
cd frontend
npm test

# End-to-end tests
npx playwright test
```

**Key test scenarios:**
1. `SystemMonitor` returns valid metrics with correct structure
2. `AnomalyDetector` scores known-malicious patterns above threshold
3. `AnomalyDetector` scores normal behavior below threshold
4. API endpoints return correct HTTP status codes and JSON schemas
5. WebSocket streams data within 2s of connection
6. Dashboard renders process list and charts without errors
7. Whitelist prevents alerts for approved processes
8. Threat history query filters work correctly
