"""HTML report generator for AI Governance Framework."""
import os
from dataclasses import asdict
from html import escape


def generate_html(summary, results, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    dec_color = {"BLOCKED": "#ff3b30", "WARNED": "#ff9500", "ALLOWED": "#34c759"}
    sev_color = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500", "MEDIUM": "#ffcc00", "LOW": "#34c759"}

    rows = []
    for i, r in enumerate(results):
        dc = dec_color.get(r.decision, "#888")
        viols_html = ""
        for v in r.violations:
            sc = sev_color.get(v.severity, "#888")
            viols_html += f'<div class="viol"><span class="sv" style="background:{sc}">{v.severity}</span> <b>{v.rule_id}</b> {escape(v.rule_name)} <code>{escape(v.matched_text)}</code><div class="rem">{escape(v.remediation)}</div></div>'

        rows.append(f"""
        <div class="scan" data-dec="{r.decision}">
          <div class="shead" onclick="toggle({i})">
            <span class="dec" style="background:{dc}">{r.decision}</span>
            <span class="usr">{escape(r.user)}</span>
            <span class="tool">{escape(r.tool)}</span>
            <span class="model">{escape(r.model)}</span>
            <span class="vcnt">{r.total_violations} violations</span>
          </div>
          <div class="sbody" id="sb-{i}">
            <div class="meta">Hash: <code>{r.prompt_hash}</code> &middot; Role: {escape(r.role)} &middot; {r.timestamp}</div>
            {viols_html or '<div class="clean">No violations detected</div>'}
          </div>
        </div>""")

    block_rate = summary.get("block_rate", 0)
    br_color = "#ff3b30" if block_rate > 30 else "#ff9500" if block_rate > 10 else "#34c759"

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AI Governance Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0f1a;color:#cbd5e1;margin:0;padding:24px;max-width:1100px;margin:auto}}
h1{{color:#a78bfa;margin:0 0 4px;font-size:26px}}
.sub{{color:#64748b;font-size:13px;margin-bottom:24px}}
.hero{{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:24px;margin-bottom:20px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}}
.big{{font-size:48px;font-weight:900;color:{br_color};line-height:1}}
.bigl{{font-size:11px;color:#64748b;text-transform:uppercase}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;flex:1}}
.s{{background:#020617;border:1px solid #1e293b;border-radius:10px;padding:12px}}
.s .n{{font-size:22px;font-weight:800}} .s .l{{font-size:10px;color:#64748b;text-transform:uppercase}}
.scan{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;margin-bottom:10px;overflow:hidden}}
.shead{{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer}}
.shead:hover{{background:#131e35}}
.dec{{color:#000;font-weight:800;font-size:10px;padding:3px 10px;border-radius:10px;min-width:70px;text-align:center}}
.usr{{color:#e2e8f0;font-weight:600;min-width:120px}} .tool{{color:#a78bfa;font-size:12px;min-width:80px}}
.model{{color:#64748b;font-size:11px;flex:1}} .vcnt{{color:#94a3b8;font-size:11px}}
.sbody{{display:none;padding:14px 18px;border-top:1px solid #1e293b}}
.sbody.open{{display:block}}
.meta{{color:#475569;font-size:11px;margin-bottom:10px}}
code{{background:#020617;padding:2px 6px;border-radius:4px;color:#fbbf24;font-size:11px}}
.viol{{background:#020617;border-left:3px solid #ff3b30;padding:10px 14px;border-radius:4px;margin:6px 0;font-size:12px}}
.sv{{color:#000;font-weight:800;font-size:9px;padding:2px 6px;border-radius:8px;margin-right:6px}}
.rem{{color:#64748b;font-size:11px;margin-top:6px;padding-left:8px;border-left:2px solid #1e293b}}
.clean{{color:#34c759;font-size:12px;padding:8px}}
.footer{{margin-top:30px;color:#334155;font-size:11px;text-align:center}}
</style></head><body>
<h1>AI Tool Security Governance Report</h1>
<div class="sub">Enterprise AI usage policy enforcement &middot; DLP + RBAC + audit trail</div>
<div class="hero">
  <div><div class="big">{block_rate}%</div><div class="bigl">Block Rate</div></div>
  <div class="stats">
    <div class="s"><div class="n">{summary['total']}</div><div class="l">Scans</div></div>
    <div class="s"><div class="n" style="color:#ff3b30">{summary['blocked']}</div><div class="l">Blocked</div></div>
    <div class="s"><div class="n" style="color:#ff9500">{summary['warned']}</div><div class="l">Warned</div></div>
    <div class="s"><div class="n" style="color:#34c759">{summary['allowed']}</div><div class="l">Allowed</div></div>
  </div>
</div>
{''.join(rows)}
<div class="footer">AI Tool Security Governance Framework &middot; github.com/CyberEnthusiastic</div>
<script>function toggle(i){{document.getElementById('sb-'+i).classList.toggle('open');}}</script>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
