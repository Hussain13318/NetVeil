"""
reporter.py — HTML Report Generator
Builds a clean, self-contained HTML report from scan results.
"""

import os
from datetime import datetime


def generate(results: dict, target: str) -> str:
    os.makedirs("reports", exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join("reports", f"netveil_{target.replace('.', '_')}_{ts}.html")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(_build_html(results, target))

    return filename


# ──────────────────────────────────────────────────────────────────────────────

def _section(title: str, content: str) -> str:
    return f"""
    <div class="card">
      <div class="card-header">{title}</div>
      <div class="card-body">{content}</div>
    </div>"""


def _table(rows: dict) -> str:
    if not rows:
        return "<p class='empty'>No data returned.</p>"
    html = "<table>"
    for k, v in rows.items():
        html += f"<tr><td class='key'>{k}</td><td>{v}</td></tr>"
    html += "</table>"
    return html


def _build_html(results: dict, target: str) -> str:
    target    = results.get("target", target)
    timestamp = results.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    sections_html = ""

    # ── DNS ──────────────────────────────────────────────────────────
    if "dns" in results:
        rows = {rtype: "<br>".join(vals) for rtype, vals in results["dns"].items()}
        sections_html += _section("DNS Records", _table(rows))

    # ── WHOIS ────────────────────────────────────────────────────────
    if "whois" in results:
        sections_html += _section("WHOIS Lookup", _table(results["whois"]))

    # ── Subdomains ───────────────────────────────────────────────────
    if "subdomains" in results:
        subs = results["subdomains"]
        if subs:
            rows = {item["subdomain"]: ", ".join(item["ips"]) for item in subs}
            sections_html += _section(f"Subdomains ({len(subs)} found)", _table(rows))
        else:
            sections_html += _section("Subdomains", "<p class='empty'>None discovered.</p>")

    # ── Geolocation ──────────────────────────────────────────────────
    if "geo" in results:
        sections_html += _section("IP Geolocation", _table(results["geo"]))

    # ── SSL ──────────────────────────────────────────────────────────
    if "ssl" in results:
        # Skip internal numeric keys like days_remaining
        ssl_rows = {k: v for k, v in results["ssl"].items() if k != "days_remaining"}
        sections_html += _section("SSL Certificate", _table(ssl_rows))

    # ── VirusTotal ───────────────────────────────────────────────────
    if "virustotal" in results:
        vt = results["virustotal"]
        rows = {k: str(v) for k, v in vt.items() if not isinstance(v, (dict, list))}
        sections_html += _section("VirusTotal Reputation", _table(rows))

    # ── Shodan ───────────────────────────────────────────────────────
    if "shodan" in results:
        sh = results["shodan"]
        summary = {k: str(v) for k, v in sh.items() if k not in ("ports", "vulns")}
        if "vulns" in sh:
            summary["CVEs"] = ", ".join(sh["vulns"])
        ports_html = ""
        if sh.get("ports"):
            ports_html = "<br><table><tr><th>Port</th><th>Transport</th><th>Banner</th></tr>"
            for p in sh["ports"]:
                ports_html += f"<tr><td>{p['port']}</td><td>{p['transport']}</td><td>{p['banner']}</td></tr>"
            ports_html += "</table>"
        sections_html += _section("Shodan Intelligence", _table(summary) + ports_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetVeil Report — {target}</title>
<style>
  :root {{
    --bg: #0d0f14;
    --surface: #161b22;
    --border: #30363d;
    --accent: #00d4ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d29922;
    --text: #c9d1d9;
    --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', Consolas, monospace;
    font-size: 14px;
    padding: 32px 24px;
    max-width: 960px;
    margin: 0 auto;
  }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 28px;
  }}
  header h1 {{ font-size: 28px; color: var(--accent); letter-spacing: 2px; }}
  header .meta {{ color: var(--muted); margin-top: 6px; font-size: 13px; }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
  }}
  .card-header {{
    background: #1c2128;
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    text-transform: uppercase;
  }}
  .card-body {{ padding: 16px 18px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 4px; }}
  th {{
    text-align: left;
    padding: 8px 12px;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    font-size: 12px;
    text-transform: uppercase;
  }}
  tr:nth-child(even) {{ background: rgba(255,255,255,.02); }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  td.key {{ color: var(--muted); width: 220px; white-space: nowrap; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  footer {{ margin-top: 36px; text-align: center; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<header>
  <h1>⬡ NetVeil</h1>
  <div class="meta">
    <strong>Target:</strong> {target} &nbsp;|&nbsp;
    <strong>Generated:</strong> {timestamp} &nbsp;|&nbsp;
    <strong>Tool:</strong> NetVeil v1.0
  </div>
</header>

{sections_html}

<footer>Generated by NetVeil &mdash; OSINT &amp; Threat Recon Intelligence Tool</footer>
</body>
</html>"""
