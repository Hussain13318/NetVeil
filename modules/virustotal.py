"""
virustotal.py — VirusTotal Domain / IP Reputation
Requires a free API key: https://www.virustotal.com/gui/join-us
Free tier: 500 lookups/day
"""

import socket
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from config import VIRUSTOTAL_API_KEY

VT_BASE = "https://www.virustotal.com/api/v3"


def _is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        return False


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] VirusTotal Reputation[/bold cyan]", expand=False))
    results = {}

    if VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        console.print("  [yellow][!] VirusTotal API key not set in config.py — skipping.[/yellow]")
        console.print()
        return results

    endpoint = (
        f"{VT_BASE}/ip_addresses/{target}"
        if _is_ip(target)
        else f"{VT_BASE}/domains/{target}"
    )

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=15)

        if resp.status_code == 401:
            console.print("  [red][!] Invalid VirusTotal API key.[/red]")
            console.print()
            return results
        if resp.status_code == 429:
            console.print("  [yellow][!] VirusTotal rate limit reached. Try again later.[/yellow]")
            console.print()
            return results
        if resp.status_code != 200:
            console.print(f"  [red][!] VirusTotal API returned HTTP {resp.status_code}[/red]")
            console.print()
            return results

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        if malicious > 5:
            risk_label = "[bold red]  HIGH RISK  [/bold red]"
        elif malicious > 0 or suspicious > 0:
            risk_label = "[bold yellow]  SUSPICIOUS  [/bold yellow]"
        else:
            risk_label = "[bold green]  CLEAN  [/bold green]"

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=22, no_wrap=True)
        table.add_column("Value", style="white")

        table.add_row("Risk Level",        risk_label)
        table.add_row("Malicious",         f"[red]{malicious}[/red] / {total} engines")
        table.add_row("Suspicious",        f"[yellow]{suspicious}[/yellow] / {total} engines")
        table.add_row("Harmless",          f"[green]{harmless}[/green] / {total} engines")
        table.add_row("Undetected",        f"{undetected} / {total} engines")

        reputation = attrs.get("reputation", 0)
        table.add_row("Reputation Score",  str(reputation))

        categories = attrs.get("categories", {})
        if categories:
            cats = list(set(categories.values()))[:4]
            table.add_row("Categories",    ", ".join(cats))
            results["categories"] = cats

        last_seen = attrs.get("last_modification_date")
        if last_seen:
            import datetime
            table.add_row("Last Analysis",
                          datetime.datetime.utcfromtimestamp(last_seen).strftime("%Y-%m-%d"))

        console.print(table)

        results.update({
            "risk":        risk_label,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "harmless":    harmless,
            "total":       total,
            "reputation":  reputation,
        })

    except requests.RequestException as e:
        console.print(f"  [red][!] VirusTotal request failed: {e}[/red]")
    except Exception as e:
        console.print(f"  [red][!] VirusTotal error: {e}[/red]")

    console.print()
    return results
