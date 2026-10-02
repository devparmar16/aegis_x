# Aegis-X — Download Inspection Engine

The first module of Aegis-X, an Endpoint Exposure Management platform.
This module monitors Google Chrome's Downloads folder, inspects every
newly-completed download, scores it with a deterministic risk engine,
optionally asks an AI provider to explain the evidence in plain
language, persists the full report to SQLite, and pops up a desktop
report window.

## Architecture

```
backend/app/
  collectors/    Independent evidence gatherers + the download watcher
                  base_watcher.py     - abstract interface for any browser
                  chrome_watcher.py   - Chrome implementation (watchdog-based)
                  file_info_collector.py - name, size, timestamps, MIME, entropy
                  hash_collector.py      - SHA256 / MD5
                  pe_collector.py        - PE header, ASLR/DEP/CFG, imports, sections
                  signature_collector.py - Authenticode status + publisher
                                            (uses WinVerifyTrust only if
                                            running on Windows; on Linux/
                                            REMnux it degrades to reading
                                            the publisher out of the PE
                                            certificate table and reports
                                            signature status as "unknown"
                                            rather than failing — this is
                                            expected when analyzing Windows
                                            PE samples from a Linux host)
  analysis/      FileAnalyzer orchestrates collectors into a FileReport.
                  Knows nothing about *how* a file was discovered.
  risk/          RiskEngine — deterministic, weighted scoring. The ONLY
                  authority on severity. AI never touches this.
  ai/            AIProvider abstraction + Groq / Gemini / OpenAI / Ollama /
                  Null implementations, selected via AI_PROVIDER in .env.
                  Explanatory only — cannot set severity or score.
  database/      SQLite persistence (DatabaseManager).
  ui/            Tkinter popup report window (ReportPopup).
  models/        Shared Pydantic contracts (FileReport, RiskAssessment, ...)
                  used by every layer above — this is what keeps the
                  layers decoupled from each other.
  config/        The ONLY module that reads environment variables.
  utils/         Shared logging setup.
  api/           Optional read-only FastAPI layer for browsing stored
                  reports (separate from the desktop pipeline).
  main.py        Wiring + threading model (watcher thread -> worker
                  thread -> Tk main thread for the popup).
```

### Why this decoupling matters

Every cross-layer interaction happens through the Pydantic models in
`app/models/`, not through direct calls into another layer's internals.
Concretely:

- Adding a new browser: implement `BaseDownloadWatcher`, call
  `on_new_file(path)`. Nothing in analysis/risk/AI/UI changes.
- Adding a new AI backend: implement `AIProvider.analyze()`, register it
  in `ai_factory.py`. Nothing else changes.
- Adding a new risk factor: write one evaluator method, add one line to
  `RiskEngine._evaluators`. Scoring math is untouched.
- Swapping SQLite for another store: reimplement `DatabaseManager`'s
  public methods; callers never touch SQL directly.

This same shape is meant to extend to future modules (Browser
Protection, Execution Monitoring, Attack Path Analysis, Persistence
Monitoring) sharing the `collectors` / `analysis` / `risk` pattern.

## Setup — REMnux (Ubuntu Linux x86_64)

The target deployment environment is REMnux. One script handles system
packages, the virtualenv, Python dependencies, and `.env` creation:

```bash
chmod +x setup.sh
./setup.sh
```

Then edit `backend/.env` — at minimum set `CHROME_DOWNLOAD_PATH` to a
real folder on the VM (e.g. `/home/remnux/Downloads`).

The Linux/REMnux flow is the primary target, but the core Python app can
also be installed manually on Windows with PowerShell.

## Setup — Windows 10/11 (PowerShell)

If you want to run the project on Windows, use PowerShell and set up
the virtual environment manually:

```powershell
cd backend
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Then edit `backend\.env` and set `CHROME_DOWNLOAD_PATH` to your actual
Downloads folder, for example `C:\Users\YourName\Downloads`.

If PowerShell blocks activation scripts, run this once in an elevated or
current-user session:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

On Windows, `setup.sh` is not used.

### Manual setup (equivalent to setup.sh)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip python3-tk libmagic1
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit it
```

## Run

### Windows (PowerShell)

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python -m app.main
```

Open a second PowerShell window for the dashboard/API if you want it:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python -m app.api.server
```

```bash
source backend/venv/bin/activate
cd backend
python -m app.main
```

This starts the Chrome downloads watcher and the analysis worker
thread. If a working X display is available (REMnux's Xfce desktop, or
X11 forwarding over SSH), a Tkinter report popup appears automatically
after each analysis. **If no display is detected, Aegis-X logs a
warning and runs headless automatically** — the watcher, analyzer, risk
engine, AI layer, and database all keep working exactly the same; only
the popup is skipped. This makes it safe to run over a plain SSH
session with no X forwarding.

## Web dashboard + JSON API (Firefox / curl)

Run in a separate terminal:

```bash
source backend/venv/bin/activate
cd backend
python -m app.api.server
```

Binds to `API_HOST:API_PORT` from `.env` (default `127.0.0.1:8000`).

- **Firefox (inside the VM):** open `http://127.0.0.1:8000/` for a
  browsable dashboard of every analyzed download, with a detail page
  per report (`/reports/{id}/view`).
- **curl / scripting:**
  ```bash
  curl http://127.0.0.1:8000/health
  curl http://127.0.0.1:8000/reports
  curl http://127.0.0.1:8000/reports/1
  ```

To reach the dashboard from the VirtualBox host or another machine on a
host-only network, set `API_HOST=0.0.0.0` in `.env` before starting
`app.api.server`, and configure the corresponding VirtualBox network
adapter / port forward.

## Configuration

All configuration lives in `.env` (see `.env.example` for every
supported key). Nothing is hardcoded — paths, API keys, model names,
log level, and the AI provider selection are all environment-driven and
read exclusively through `app/config/config.py`.

## What this module deliberately does NOT do

Per the Aegis-X scope for this first module: no real-time protection, no
file deletion or quarantine, no browser extensions, no kernel drivers,
no attack graphs, no network monitoring. Those are reserved for later
modules (Browser Protection, Execution Monitoring, Attack Path
Analysis, Persistence Monitoring) that will reuse this same
collector/analysis/risk pattern.
