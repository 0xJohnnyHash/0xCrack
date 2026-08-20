"""
html_report.py
==============
Renderiza un AuditReport a un informe HTML autonomo (un solo archivo, sin
dependencias externas), listo para adjuntar en un pentest o mostrar en el
portafolio. Paleta oscura consistente con la GUI.
"""

from __future__ import annotations

import html
from ..core.audit import AuditReport

_SEV_COLOR = {
    "CRITICAL": "#ff5c7a",
    "HIGH": "#ff9f43",
    "MEDIUM": "#f6c945",
    "LOW": "#4dd4ac",
}


def _bar(label, value, maxv, color="#4da3ff"):
    pct = (value / maxv * 100) if maxv else 0
    return f"""
    <div class="bar-row">
      <span class="bar-label">{html.escape(str(label))}</span>
      <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;background:{color}"></div></div>
      <span class="bar-val">{value}</span>
    </div>"""


def render(report: AuditReport) -> str:
    s = report.stats

    # Distribucion de longitudes.
    length_bars = ""
    if s.get("length_distribution"):
        maxc = max(s["length_distribution"].values())
        for length, count in s["length_distribution"].items():
            length_bars += _bar(f"{length} chars", count, maxc)

    # Patrones.
    pattern_bars = ""
    if s.get("top_patterns"):
        maxp = max(c for _, c in s["top_patterns"])
        for name, count in s["top_patterns"]:
            pattern_bars += _bar(name, count, maxp, "#c77dff")

    # Hallazgos.
    findings_html = ""
    for f in report.findings:
        color = _SEV_COLOR.get(f["severity"], "#888")
        findings_html += f"""
        <div class="finding">
          <div class="sev" style="background:{color}">{f['severity']}</div>
          <div class="finding-body">
            <h4>{html.escape(f['title'])}</h4>
            <p>{html.escape(f['detail'])}</p>
            <p class="remediation"><strong>Remediation:</strong> {html.escape(f['remediation'])}</p>
          </div>
        </div>"""

    # Reuse.
    reuse_rows = ""
    for pw, count in (s.get("reused_passwords") or {}).items():
        masked = pw[0] + "*" * (len(pw) - 1) if pw else ""
        reuse_rows += f"<tr><td>{html.escape(masked)}</td><td>{count} accounts</td></tr>"
    if not reuse_rows:
        reuse_rows = "<tr><td colspan='2' style='color:#4dd4ac'>No reuse detected</td></tr>"

    # Detail table (password masked so credentials never leak into the report).
    detail_rows = ""
    for p in report.per_password:
        pw = p["password"]
        masked = pw[:2] + "*" * max(0, len(pw) - 2)
        issues = ", ".join(p["policy_issues"]) or "—"
        badge = "ok" if p["compliant"] else "bad"
        rank = p.get("breach_rank")
        breach_cell = (f"<span style='color:#ff5c7a'>#{rank}</span>"
                       if rank else "<span style='color:#4dd4ac'>no</span>")
        detail_rows += f"""
        <tr>
          <td class="mono">{html.escape(masked)}</td>
          <td>{p['length']}</td>
          <td>{p['entropy_bits']} bits</td>
          <td>{html.escape(p['strength'])}</td>
          <td>{breach_cell}</td>
          <td class="{badge}">{html.escape(issues)}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>0xCrack · Password Audit Report</title>
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --border:#2a3140;
    --text:#e6edf3; --muted:#8b98a9; --accent:#4da3ff; --accent2:#c77dff;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
    font-family:'Segoe UI',system-ui,-apple-system,sans-serif; line-height:1.55; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:40px 24px; }}
  header {{ display:flex; align-items:center; justify-content:space-between;
    border-bottom:1px solid var(--border); padding-bottom:20px; margin-bottom:28px; }}
  .brand {{ font-size:26px; font-weight:700; letter-spacing:.5px; }}
  .brand span {{ color:var(--accent); }}
  .meta {{ text-align:right; color:var(--muted); font-size:13px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:32px; }}
  .kpi {{ background:var(--panel); border:1px solid var(--border); border-radius:12px;
    padding:18px; text-align:center; }}
  .kpi .num {{ font-size:30px; font-weight:700; }}
  .kpi .lbl {{ color:var(--muted); font-size:12px; text-transform:uppercase;
    letter-spacing:.6px; margin-top:4px; }}
  h2 {{ font-size:18px; margin:34px 0 14px; padding-left:10px;
    border-left:3px solid var(--accent); }}
  .panel {{ background:var(--panel); border:1px solid var(--border);
    border-radius:12px; padding:20px; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:7px 0; font-size:13px; }}
  .bar-label {{ width:110px; color:var(--muted); }}
  .bar-track {{ flex:1; height:10px; background:var(--panel2); border-radius:6px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:6px; }}
  .bar-val {{ width:34px; text-align:right; color:var(--muted); }}
  .finding {{ display:flex; gap:14px; background:var(--panel); border:1px solid var(--border);
    border-radius:12px; padding:16px; margin-bottom:12px; }}
  .sev {{ align-self:flex-start; color:#0d1117; font-weight:700; font-size:11px;
    padding:4px 10px; border-radius:20px; letter-spacing:.5px; }}
  .finding h4 {{ margin:0 0 6px; }}
  .finding p {{ margin:4px 0; color:var(--muted); font-size:14px; }}
  .remediation {{ color:var(--text)!important; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); }}
  th {{ color:var(--muted); text-transform:uppercase; font-size:11px; letter-spacing:.5px; }}
  .mono {{ font-family:'Consolas',monospace; }}
  td.bad {{ color:#ff9f43; }} td.ok {{ color:#4dd4ac; }}
  footer {{ margin-top:36px; padding-top:18px; border-top:1px solid var(--border);
    color:var(--muted); font-size:12px; text-align:center; }}
  .disclaimer {{ background:#1c1206; border:1px solid #4a3410; color:#f6c945;
    border-radius:10px; padding:12px 16px; font-size:12px; margin-bottom:26px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">0x<span>Crack</span></div>
    <div class="meta">
      Password audit report<br>
      Analyst: {html.escape(report.analyst)}<br>
      {html.escape(report.generated_at)}
    </div>
  </header>

  <div class="disclaimer">
    Generated from an AUTHORIZED audit exercise on hashes legitimately held by the
    analyst. Passwords are shown masked.
  </div>

  <div class="kpis">
    <div class="kpi"><div class="num">{report.total_hashes}</div><div class="lbl">Hashes</div></div>
    <div class="kpi"><div class="num">{report.cracked_count}</div><div class="lbl">Cracked</div></div>
    <div class="kpi"><div class="num">{report.crack_rate}%</div><div class="lbl">Rate</div></div>
    <div class="kpi"><div class="num">{s.get('avg_entropy_bits',0)}</div><div class="lbl">Avg bits</div></div>
  </div>

  <h2>Prioritized findings</h2>
  {findings_html or '<div class="panel">No findings.</div>'}

  <h2>Distribution &amp; patterns</h2>
  <div class="grid2">
    <div class="panel"><strong>Password length</strong>{length_bars or '<p>—</p>'}</div>
    <div class="panel"><strong>Detected patterns</strong>{pattern_bars or '<p>—</p>'}</div>
  </div>

  <h2>Password reuse</h2>
  <div class="panel"><table>
    <tr><th>Password (masked)</th><th>Reuse</th></tr>
    {reuse_rows}
  </table></div>

  <h2>Per-credential detail</h2>
  <div class="panel"><table>
    <tr><th>Password</th><th>Len</th><th>Entropy</th><th>Strength</th><th>Breach</th><th>Policy issues</th></tr>
    {detail_rows or '<tr><td colspan=6>No data</td></tr>'}
  </table></div>

  <footer>
    Generated by <strong>0xCrack</strong> · Author: Johnny Hash (0xJohnnyHash) ·
    Offensive/defensive security auditing tool · Authorized use only
  </footer>
</div>
</body>
</html>"""


def save(report: AuditReport, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(report))
    return path
