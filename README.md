# Aegis-X — Endpoint Exposure & Threat Intelligence Platform

> **"Detection is commoditized; Intelligence is the differentiator."**

**Aegis-X** is an advanced Endpoint Threat Intelligence and Evidence-Fusion platform designed for Windows. Instead of relying on isolated scanner alerts, Aegis-X gathers sensory data across files, running processes, network connections, and background services, then correlates them through a **Context-Aware Risk Engine** to deliver explainable, actionable threat assessments.

---

## ⚡ Key Features

- **🧠 Evidence Fusion & Context-Aware Risk Engine**: Correlates multiple detection vectors (YARA, ClamAV, PE heuristics, signature status, network activity) into a unified risk score (0–100) with deterministic, transparent severity levels.
- **📁 Multi-Engine File Analysis**:
  - PE header parsing (Imports, Exports, Sections, Compile Time, Anomalous permissions like `W^X`).
  - Cryptographic hashing (MD5, SHA1, SHA256) and Shannon entropy calculation.
  - Multi-layer scanner integrations: YARA rules, ClamAV daemon/clamscan, and Archive inspection (ZIP, TAR, GZ).
  - Authenticode digital signature checking via Win32 `WinVerifyTrust`.
- **⚙️ Process & Runtime Forensics**: Real-time process monitoring, identifying unsigned binaries running from temporary or user-writable locations (`AppData`, `Temp`, `Downloads`).
- **🌐 Network Socket Correlation**: Inspects active connections and listening ports, linking network sockets directly back to their originating PIDs.
- **🛠️ Windows Service Scanner**: High-performance C-level inspection of Windows background services to catch persistence mechanisms.
- **👁️ Real-Time Folder Sentinel**: Background watcher monitoring critical ingress directories (e.g. `Downloads`, `Temp`) with non-blocking scans.
- **🖥️ Responsive CustomTkinter UI**: Modern, dark-themed desktop interface with one-click page navigation and thread-safe asynchronous updates.

---

## 🏗️ Architecture

```text
aegis-x/backend/app/
├── collectors/          Sensory evidence gatherers (File, Process, Network, Services, Watchdog)
├── scanners/            Scanning engines (YARA, ClamAV, Archive, Threat Intel interface)
├── analysis/            FileAnalyzer & orchestrators producing standardized FileReports
├── risk/                Deterministic weighted RiskEngine (Scoring authority)
├── correlation/         Graph and relationship mapping (File <-> Process <-> Network <-> Service)
├── database/            SQLite persistence layer for scan reports & system events
├── models/              Pydantic contracts decoupling all system components
├── ui/                  CustomTkinter desktop GUI (Dashboard, File Scanner, Monitors, Reports)
└── main.py              Application entry point and lifecycle orchestration
```

---

## 🚀 Quick Start (Windows)

### Prerequisites
- Windows 10/11
- Python 3.10+ (Recommended: Python 3.11)

### 1. Open Terminal & Navigate to Backend
```powershell
cd aegis-x\backend
```

### 2. Activate Virtual Environment
```powershell
.\myenv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

### 3. Install Dependencies (If not already installed)
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment
Ensure `.env` exists in `aegis-x/backend/`:
```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

### 5. (Optional) Generate Safe Demo Samples
Generate safe test files (e.g. EICAR test string, extension mismatches) to test threat detection:
```powershell
python create_demo_samples.py
```

### 6. Run Aegis-X
```powershell
python -m app.main
```

---

## 📊 Modules Overview

| Section | Icon | Functionality |
| :--- | :---: | :--- |
| **Dashboard** | 📊 | Real-time threat status, CPU/RAM telemetry gauges, and recent scan logs. |
| **File Scanner** | 🔍 | On-demand scanning of files/folders with hash, PE, YARA, and ClamAV analysis. |
| **Process Monitor** | ⚙️ | Live process table highlighting unsigned binaries and anomalous memory/paths. |
| **Network Monitor** | 🌐 | Active sockets and listening ports mapped directly to owning PIDs. |
| **Windows Services**| 🛠️ | Instant enumeration of installed Win32 background services and startup types. |
| **Reports & History**| 📜 | Historical audit ledger of all analyzed files and threat reports. |
| **Settings** | ⚙️ | Engine toggles (YARA/ClamAV), API keys, and scan preferences. |

---

## 🛡️ License
Private / Proprietary development.
