"""
FastAPI layer exposing stored reports both as a browsable HTML dashboard
(for Firefox) and as a JSON API (for curl / other tooling / future
Aegis-X modules).

This is intentionally read-only and decoupled from the watcher/analysis
pipeline in `app.main` — it queries the same SQLite database but never
touches collectors, the risk engine, or the AI layer directly.

Run standalone:

    python -m app.api.server

which binds to API_HOST:API_PORT from .env (default 127.0.0.1:8000).
For access from other machines/hosts on a VirtualBox host-only network,
set API_HOST=0.0.0.0 in .env.

Endpoints:
    GET /                   HTML dashboard (Firefox-friendly)
    GET /reports/{id}/view  HTML detail view for one report
    GET /health             {"status": "ok"} — plain JSON, curl-friendly
    GET /reports            JSON list of recent reports
    GET /reports/{id}       JSON detail for one report
"""

from __future__ import annotations

import html
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from app.config.config import get_config
from app.database.db_manager import DatabaseManager
from app.models.file_report import FileReport, Severity
from app.utils.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(
    title="Aegis-X — Download Inspection Engine API",
    description="Browsable dashboard (Firefox) and JSON API (curl) for "
                "analyzed download reports.",
    version="0.1.0",
)

_config = get_config()
_db = DatabaseManager(_config.database_path)

_SEVERITY_COLORS = {
    Severity.LOW: "#2e7d32",
    Severity.MEDIUM: "#f9a825",
    Severity.HIGH: "#ef6c00",
    Severity.CRITICAL: "#c62828",
}

_PAGE_STYLE = """
body { background:#1e1f26; color:#e8e8ec; font-family: -apple-system, 'Segoe UI', sans-serif; margin:0; padding:24px; }
h1 { font-size:20px; }
a { color:#8ab4f8; text-decoration:none; }
a:hover { text-decoration:underline; }
table { width:100%; border-collapse:collapse; margin-top:16px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #33343f; font-size:13px; }
th { color:#9a9ba5; font-weight:600; text-transform:uppercase; font-size:11px; }
.badge { display:inline-block; padding:3px 10px; border-radius:4px; color:white; font-weight:600; font-size:12px; }
.panel { background:#2a2b35; border-radius:8px; padding:16px 20px; margin-bottom:14px; }
.muted { color:#9a9ba5; }
.mono { font-family: 'SF Mono', Consolas, monospace; font-size:12px; word-break:break-all; }
"""


def _severity_badge(severity: Severity) -> str:
    color = _SEVERITY_COLORS.get(severity, "#555")
    return f'<span class="badge" style="background:{color}">{html.escape(severity.value)}</span>'


@app.get("/health")
def health_check() -> dict:
    """Basic liveness check — plain JSON for curl/monitoring."""
    return {"status": "ok"}


@app.get("/reports", response_model=List[FileReport])
def list_reports(limit: int = 50) -> List[FileReport]:
    """Return the most recently analyzed reports, newest first (JSON)."""
    return _db.list_recent_reports(limit=limit)


@app.get("/reports/{report_id}", response_model=FileReport)
def get_report(report_id: int) -> FileReport:
    """Return a single report by its database id (JSON)."""
    report = _db.get_report_by_id(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return report


@app.get("/", response_class=HTMLResponse)
def dashboard(limit: int = 100) -> str:
    """Browsable HTML dashboard listing recent reports."""
    reports = _db.list_recent_reports(limit=limit)

    rows = []
    for r in reports:
        severity = r.risk.severity if r.risk else Severity.LOW
        score = r.risk.score if r.risk else 0.0
        rows.append(
            f"<tr>"
            f"<td>{html.escape(r.analyzed_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f"<td><a href='/reports/{r.report_id}/view'>{html.escape(r.metadata.filename)}</a></td>"
            f"<td class='mono'>{html.escape(r.hashes.sha256[:16])}...</td>"
            f"<td>{_severity_badge(severity)}</td>"
            f"<td>{score:.0f}/100</td>"
            f"<td>{'Yes' if r.metadata.is_executable else 'No'}</td>"
            f"</tr>"
        )

    body = "".join(rows) or "<tr><td colspan='6' class='muted'>No reports yet.</td></tr>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Aegis-X Dashboard</title>
<style>{_PAGE_STYLE}</style></head>
<body>
<h1>Aegis-X — Download Inspection Engine</h1>
<p class="muted">Showing {len(reports)} most recent analyzed downloads.
Programmatic access: <code>curl http://{html.escape(_config.api_host)}:{_config.api_port}/reports</code></p>
<table>
<tr><th>Analyzed</th><th>Filename</th><th>SHA256</th><th>Severity</th><th>Score</th><th>Executable</th></tr>
{body}
</table>
</body></html>"""


@app.get("/reports/{report_id}/view", response_class=HTMLResponse)
def report_view(report_id: int) -> str:
    """Browsable HTML detail page for a single report."""
    report = _db.get_report_by_id(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    m, h, s = report.metadata, report.hashes, report.signature
    risk = report.risk
    ai = report.ai_explanation

    factors_html = ""
    if risk:
        triggered = [f for f in risk.factors if f.triggered]
        factors_html = "".join(
            f"<li>{html.escape(f.description)} <span class='muted'>(weight {f.weight:.0f})</span></li>"
            for f in triggered
        ) or "<li class='muted'>No risk factors triggered.</li>"

    pe_html = ""
    if report.pe_info:
        pe = report.pe_info
        pe_html = f"""
<div class="panel"><h3>PE Security Features</h3>
<p>Architecture: {html.escape(pe.architecture or '—')} &nbsp; Type: {html.escape(pe.executable_type or '—')}</p>
<p>ASLR: {'Enabled' if pe.aslr_enabled else 'Disabled'} &nbsp;
DEP/NX: {'Enabled' if pe.dep_nx_enabled else 'Disabled'} &nbsp;
CFG: {'Enabled' if pe.cfg_enabled else 'Disabled'}</p>
<p class="mono">Sections: {html.escape(', '.join(pe.section_names) or '—')}</p>
<p class="mono">Suspicious imports: {html.escape(', '.join(pe.suspicious_imports) or 'None')}</p>
</div>"""

    ai_html = ""
    if ai:
        if ai.error:
            ai_html = f"<div class='panel'><h3>AI Explanation ({html.escape(ai.provider)})</h3><p class='muted'>Unavailable: {html.escape(ai.error)}</p></div>"
        else:
            ai_html = f"""
<div class="panel"><h3>AI Explanation ({html.escape(ai.provider)})</h3>
<p><b>What it appears to be:</b> {html.escape(ai.what_it_appears_to_be)}</p>
<p><b>Why the evidence matters:</b> {html.escape(ai.why_evidence_matters)}</p>
<p><b>Possible attack techniques:</b> {html.escape(ai.possible_attack_techniques)}</p>
<p><b>Potential impact:</b> {html.escape(ai.potential_impact)}</p>
<p><b>Recommended precautions:</b> {html.escape(ai.recommended_precautions)}</p>
<p><b>Confidence:</b> {html.escape(ai.confidence_level)}</p>
</div>"""

    severity = risk.severity if risk else Severity.LOW
    score = risk.score if risk else 0.0

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Aegis-X — {html.escape(m.filename)}</title>
<style>{_PAGE_STYLE}</style></head>
<body>
<p><a href="/">&larr; Back to dashboard</a></p>
<h1>{html.escape(m.filename)} {_severity_badge(severity)} <span class="muted">{score:.0f}/100</span></h1>

<div class="panel"><h3>File Information</h3>
<p class="mono">{html.escape(m.absolute_path)}</p>
<p>Size: {m.size_bytes:,} bytes &nbsp; MIME: {html.escape(m.mime_type)} &nbsp; Entropy: {m.entropy:.2f}/8.0 &nbsp; Executable: {'Yes' if m.is_executable else 'No'}</p>
</div>

<div class="panel"><h3>Hashes</h3>
<p class="mono">SHA256: {html.escape(h.sha256 or '—')}</p>
<p class="mono">MD5: {html.escape(h.md5 or '—')}</p>
</div>

<div class="panel"><h3>Digital Signature</h3>
<p>Status: {html.escape(s.status.value.replace('_',' ').title())} &nbsp; Publisher: {html.escape(s.publisher or 'Unknown')}</p>
</div>

{'' if not report.scanner_results else ''.join(
    f"<div class='panel'><h3>{html.escape(result.scanner_name)} Scanner</h3>"
    f"<p>Status: {html.escape(result.status.value)} &nbsp; Severity: {html.escape(result.severity)} &nbsp; Confidence: {result.confidence:.2f} &nbsp; Time: {result.execution_time_ms:.0f} ms</p>"
    f"<p class='mono'>Evidence: {html.escape('; '.join(result.evidence) or '—')}</p>"
    f"<p class='mono'>Errors: {html.escape('; '.join(result.errors) or '—')}</p></div>"
    for result in report.scanner_results
)}

{pe_html}

<div class="panel"><h3>Reasons for Score</h3><ul>{factors_html}</ul></div>

{ai_html}
</body></html>"""


def run() -> None:
    """Start uvicorn bound to the configured host/port. Entry point for
    `python -m app.api.server`.
    """
    import uvicorn

    logger.info("Starting Aegis-X API/dashboard on %s:%s", _config.api_host, _config.api_port)
    uvicorn.run(app, host=_config.api_host, port=_config.api_port)


if __name__ == "__main__":
    run()
