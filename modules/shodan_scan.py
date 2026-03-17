"""
shodan_scan.py — Shodan Host Intelligence
Retrieves open ports, running services, OS, and known CVEs.
Requires a free API key: https://account.shodan.io/register
"""

import socket
import shodan
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from config import SHODAN_API_KEY


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] Shodan Intelligence[/bold cyan]", expand=False))
    results = {}

    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        console.print("  [yellow][!] Shodan API key not set in config.py — skipping.[/yellow]")
        console.print()
        return results

    ip = _resolve(target)
    if ip != target:
        console.print(f"  [dim]Resolved {target} → {ip}[/dim]")

    try:
        api  = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        # ── Host summary ──────────────────────────────────────────────
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=22, no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("IP Address",    host.get("ip_str", ip))
        table.add_row("Organization",  host.get("org",  "N/A"))
        table.add_row("ISP",           host.get("isp",  "N/A"))
        table.add_row("OS",            host.get("os",   "Unknown") or "Unknown")
        table.add_row("Country",       host.get("country_name", "N/A"))
        table.add_row("Last Updated",  host.get("last_update",  "N/A"))

        vulns = host.get("vulns", [])
        if vulns:
            table.add_row(
                "CVEs Found",
                f"[bold red]{', '.join(list(vulns)[:6])}{'  …' if len(vulns) > 6 else ''}[/bold red]",
            )
            results["vulns"] = list(vulns)

        console.print(table)

        # ── Open ports ────────────────────────────────────────────────
        console.print(f"\n  [bold yellow]Open Ports / Services:[/bold yellow]")
        ports_info = []
        for service in host.get("data", []):
            port      = service.get("port")
            transport = service.get("transport", "tcp")
            product   = service.get("product", "")
            version   = service.get("version", "")
            banner    = f"{product} {version}".strip() or service.get("data", "")[:60].replace("\n", " ")
            console.print(f"    [cyan]{port}/{transport:<5}[/cyan]  [white]{banner}[/white]")
            ports_info.append({"port": port, "transport": transport, "banner": banner})

        results["ip"]    = ip
        results["org"]   = host.get("org", "N/A")
        results["ports"] = ports_info

    except shodan.APIError as e:
        msg = str(e)
        if "No information available" in msg:
            console.print(f"  [yellow][!] No Shodan data available for {target}[/yellow]")
        elif "Invalid API key" in msg:
            console.print("  [red][!] Invalid Shodan API key.[/red]")
        else:
            console.print(f"  [red][!] Shodan error: {msg}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Shodan scan failed: {e}[/red]")

    console.print()
    return results
