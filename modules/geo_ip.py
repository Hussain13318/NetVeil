"""
geo_ip.py — IP Geolocation
Uses the free ip-api.com service (no API key required).
"""

import socket
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


def _resolve(target: str) -> str:
    """Return IP address; resolve domain if needed."""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] IP Geolocation[/bold cyan]", expand=False))
    results = {}

    ip = _resolve(target)
    if ip != target:
        console.print(f"  [dim]Resolved {target} → {ip}[/dim]")

    try:
        resp = requests.get(_API.format(ip=ip), timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            console.print(f"  [red][!] {data.get('message', 'Geolocation failed')}[/red]")
            console.print()
            return results

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=20, no_wrap=True)
        table.add_column("Value", style="white")

        fields = {
            "IP Address":    data.get("query", ip),
            "Country":       f"{data.get('country', '')} ({data.get('countryCode', '')})",
            "Region":        data.get("regionName", ""),
            "City":          data.get("city", ""),
            "ZIP":           data.get("zip", ""),
            "Coordinates":   f"{data.get('lat', '')}, {data.get('lon', '')}",
            "Timezone":      data.get("timezone", ""),
            "ISP":           data.get("isp", ""),
            "Organization":  data.get("org", ""),
            "AS Number":     data.get("as", ""),
        }

        for key, value in fields.items():
            if value and value.strip(" ,"):
                table.add_row(key, value)
                results[key] = value

        console.print(table)

    except requests.RequestException as e:
        console.print(f"  [red][!] Geolocation request failed: {e}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Geolocation error: {e}[/red]")

    console.print()
    return results
