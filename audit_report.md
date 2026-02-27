# Auraveil — Full Project Audit Report

**Date:** 2026-02-24  
**Scope:** Backend (Python), Frontend (React/TypeScript), Configuration, Dependencies, Project Structure  
**Auditor:** Automated deep code review of all source files

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 3 |
| 🟠 High | 5 |
| 🟡 Medium | 8 |
| 🔵 Low | 6 |
| **Total** | **22** |

The codebase is well-structured with good separation of concerns and proper error handling in most areas. Critical issues center around missing `.gitignore`, insecure model deserialization, and SQLite thread-safety concerns. High-priority issues include unbounded memory growth and incomplete API input validation.

---

## 🔴 Critical Issues

### C1 — Missing `.gitignore`

**File:** Project root  
**Risk:** Database files, model binaries, venv, `__pycache__`, `.env` files, and `data/` artifacts will be committed to version control.

**Recommendation:** Create a `.gitignore` immediately:
```
# Python
__pycache__/
*.pyc
*.pyo
backend/venv/
*.egg-info/

# Data & Models
data/
models/
*.db
*.pkl
*.pt

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db

# Environment
.env
```

---

### C2 — Insecure `pickle.load()` for Model Deserialization

**File:** `backend/ai_engine/anomaly_detector.py` — lines 322–323  
**Risk:** `pickle.load()` can execute arbitrary code. A malicious `.pkl` file could compromise the system.

```python
with open(path, "rb") as f:
    state = pickle.load(f)  # Arbitrary code execution risk
```

**Recommendation:** Use `joblib` instead (already a scikit-learn dependency) which has safer defaults, or add integrity verification:
```python
import joblib
state = joblib.load(path)
```
Or maintain pickle but add file hash verification before loading.

---

### C3 — SQLite Thread-Safety Issues

**File:** `backend/database/models.py`  
**Risk:** Every database function creates a new connection, which is correct for thread safety. However, there is no connection pooling and no `try/finally` to ensure connections close on exceptions (e.g., line 76–98 `log_threat`).

```python
def log_threat(...) -> int:
    conn = _get_connection()    # Opens connection
    cursor = conn.cursor()
    cursor.execute(...)         # Could throw
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()                # Never reached if execute() throws
    return row_id
```

**Recommendation:** Use context managers in all functions:
```python
def log_threat(...) -> int:
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(...)
        return cursor.lastrowid
```

---

## 🟠 High Priority Issues

### H1 — Unbounded `_feature_history` Memory Growth

**File:** `backend/ai_engine/anomaly_detector.py` — line 95  
**Risk:** `self._feature_history` grows without bound. At 1 snapshot/second with ~300 processes × 7 features, this consumes increasing memory indefinitely.

```python
self._feature_history.append(avg_features)  # Never truncated
```

**Recommendation:** Cap to a rolling window:
```python
MAX_FEATURE_HISTORY = 3600  # 1 hour
if len(self._feature_history) > MAX_FEATURE_HISTORY:
    self._feature_history = self._feature_history[-MAX_FEATURE_HISTORY:]
```

---

### H2 — Unbounded `_training_data` Growth

**File:** `backend/ai_engine/anomaly_detector.py` — line 88  
**Risk:** Same issue as H1 but for `self._training_data`. If the model is trained but `accumulate_training_data` is still called (line 139 of `main.py`), training data grows indefinitely.

**Recommendation:** Cap or clear after training:
```python
MAX_TRAINING_BUFFER = 10000
self._training_data = self._training_data[-MAX_TRAINING_BUFFER:]
```

---

### H3 — `get_active_threats()` Called Per WebSocket Cycle

**File:** `backend/api/main.py` — line 177  
**Risk:** `get_active_threats()` executes a SQLite query every monitoring cycle (every 1 second). With many threats this is a performance bottleneck. It opens a new connection, queries, and closes.

```python
"active_alerts": len(get_active_threats()),  # DB query every second
```

**Recommendation:** Cache the count in memory, update it when alerts are added or resolved:
```python
active_alert_count = 0  # maintained in-memory

# Update when alert logged
active_alert_count += 1
# Update when resolved
active_alert_count -= 1
```

---

### H4 — No Rate Limiting on Kill Endpoint

**File:** `backend/api/main.py` — line 311  
**Risk:** The `/api/processes/{pid}/kill` endpoint has no authentication or rate limiting. Any local network user could abuse it to terminate processes.

**Recommendation:** At minimum, add:
- Rate limiting (e.g., max 10 kills per minute)
- Confirmation logging with the source IP
- Consider requiring a simple API key for destructive operations

---

### H5 — `requirements.txt` Contains Non-Standard `--index-url` Syntax

**File:** `backend/requirements.txt` — line 10  
**Risk:** The inline `--index-url` flag breaks `pip install -r requirements.txt` when other packages also need PyPI. Pip applies the flag globally, potentially preventing other packages from installing.

```
torch --index-url https://download.pytorch.org/whl/cpu
```

**Recommendation:** Split into base and optional requirements:
```
# requirements.txt (core)
fastapi>=0.110.0
uvicorn[standard]>=0.27.0
...

# requirements-gpu.txt (optional)
# Install separately: pip install torch --index-url ...
```

Or use a `pyproject.toml` with optional dependency groups.

---

## 🟡 Medium Priority Issues

### M1 — `signal` Module Imported But Never Used

**File:** `backend/response_engine.py` — line 8  
```python
import signal  # Unused
```

---

### M2 — `pandas` Listed as Dependency But Never Imported

**File:** `backend/requirements.txt` — line 8  
`pandas>=2.2.0` is listed but no backend module imports it. Unnecessary dependency adds weight.

---

### M3 — `msgpack` Listed as Dependency But Never Imported

**File:** `backend/requirements.txt` — line 9  
`msgpack>=1.0.0` is listed but never used anywhere in the codebase.

---

### M4 — `os` Module Imported But Unused in `response_engine.py`

**File:** `backend/response_engine.py` — line 6  
```python
import os  # Not used
```

---

### M5 — File and Network Features Computed But Not Used in Scoring

**Files:** `backend/ai_engine/feature_engineering.py` (lines 170–212), `backend/api/main.py`  
`compute_file_activity_features()` and `compute_network_features()` are defined in feature engineering but never called in the monitoring loop or anomaly detector. These Phase 2 features appear incomplete.

**Recommendation:** Either integrate them into the process scoring pipeline or mark them as planned for Phase 3.

---

### M6 — `_alerts` List in `ProcessTracker` Grows Unbounded

**File:** `backend/monitoring/process_tracker.py` — line 104  
```python
self._alerts.append(alert)  # Never capped
```

**Recommendation:** Cap to a reasonable limit:
```python
if len(self._alerts) > 1000:
    self._alerts = self._alerts[-500:]
```

---

### M7 — Frontend `package.json` Version Mismatch

**File:** `frontend/package.json` — line 4  
`"version": "0.0.0"` while `App.tsx` footer shows `v0.2.0`. These should stay in sync.

---

### M8 — `axios` Dependency Installed But Never Used

**File:** `frontend/package.json` — line 13  
`axios` is listed as a dependency, but the frontend uses native `fetch()` for all API calls (in `threatStore.ts`). Either remove `axios` or migrate to it consistently.

---

## 🔵 Low Priority Issues

### L1 — WebSocket Re-render Loop Risk

**File:** `frontend/src/hooks/useWebSocket.ts` — line 13  
```typescript
const { updateSnapshot, setConnected } = useThreatStore();
```
Destructuring from Zustand at the top level re-renders on any store change. This is mitigated by the fact that these are action functions (referentially stable), but it's worth using selector-based access consistently.

---

### L2 — No Frontend Error Boundary

**Files:** `frontend/src/App.tsx`  
No React Error Boundary component. If any child component throws, the entire dashboard crashes with a blank screen instead of showing a graceful error.

---

### L3 — `CORS_ORIGINS` Only Includes Dev Server

**File:** `backend/config.py` — line 57  
```python
CORS_ORIGINS = ["http://localhost:5173"]
```
Production deployment will need additional origins or a configurable environment variable.

---

### L4 — Hardcoded API Base URL in Frontend

**File:** `frontend/src/stores/threatStore.ts` — line 6, `frontend/src/hooks/useWebSocket.ts` — line 7  
```typescript
const API_BASE = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/ws/live';
```

**Recommendation:** Use `import.meta.env.VITE_API_BASE` for configurability.

---

### L5 — No `__init__.py` Verification

**Files:** `backend/monitoring/__init__.py`, `backend/ai_engine/__init__.py`, `backend/database/__init__.py`  
Not verified if `__init__.py` files exist in all packages. Missing `__init__.py` can cause import issues in some Python configurations.

---

### L6 — Magic Numbers in Scoring

**File:** `backend/ai_engine/anomaly_detector.py` — line 191  
```python
if_score = float(np.clip((0.5 - raw_score) * 100, 0, 100))
```
The `0.5` multiplier and the scaling factor `100` are undocumented magic numbers. Consider extracting them into named constants in config.

---

## Dependency Audit

| Package | Version | Status |
|---------|---------|--------|
| `fastapi` | ≥0.110 | ✅ OK |
| `uvicorn` | ≥0.27 | ✅ OK |
| `psutil` | ≥5.9 | ✅ OK |
| `watchdog` | ≥4.0 | ✅ OK |
| `scapy` | ≥2.5 | ✅ OK |
| `scikit-learn` | ≥1.4 | ✅ OK |
| `numpy` | ≥1.26 | ✅ OK |
| `torch` | 2.10+cpu | ✅ Installed |
| `shap` | 0.50 | ✅ Installed |
| `pandas` | ≥2.2 | ⚠️ Unused |
| `msgpack` | ≥1.0 | ⚠️ Unused |
| `axios` (frontend) | ^1.13 | ⚠️ Unused |

---

## Architecture Assessment

### Strengths
- **Clean layered architecture:** Monitoring → AI Engine → Response → API
- **Graceful degradation:** PyTorch, SHAP, and Scapy all fail gracefully with fallback behavior
- **Privacy-first design:** All processing on-device, no external API calls or cloud dependencies
- **Good error isolation:** Exception handling in the monitoring loop prevents cascading failures
- **LSTM + IF ensemble:** Smart approach blending temporal and point-in-time anomaly detection

### Areas for Improvement
- **Testing:** No unit or integration tests exist anywhere in the project
- **Logging:** Good logging coverage but no structured logging format (JSON) for production log aggregation
- **Config management:** All config is in `config.py` constants — no `.env` or environment variable overrides
- **Documentation:** No README, API docs, or developer setup guide

---

## Recommended Priority Actions

1. **Create `.gitignore`** immediately (C1) — prevents accidental leaks
2. **Replace `pickle.load()` with `joblib`** (C2) — trivial fix, high security impact
3. **Add connection context managers** in database layer (C3)
4. **Cap memory lists** (`_feature_history`, `_training_data`, `_alerts`) (H1, H2, M6)
5. **Cache active alert count** to eliminate per-second DB queries (H3)
6. **Clean up unused deps** (`pandas`, `msgpack`, `axios`, `signal`, `os`) (M1–M4, M8)
7. **Fix `requirements.txt`** `--index-url` syntax (H5)
8. **Add basic tests** for critical paths (AI scoring, response engine evaluation, database CRUD)
