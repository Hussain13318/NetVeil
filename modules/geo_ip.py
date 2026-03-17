"""
geo_ip.py — IP Geolocation
Uses the free ip-api.com service (no API key required).
"""

import ipaddress
import socket
import requests
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


def _unique(items: list) -> list:
    """Return unique items while preserving order."""
    seen = set()
    ordered = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolve_all(target: str) -> list:
    """Resolve all IPv4/IPv6 addresses for a domain; return target if already an IP."""
    if _is_ip(target):
        return [target]

    resolved = []

    # Prefer explicit DNS answers so we can capture all edge endpoints.
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(target, record_type, raise_on_no_answer=False)
            for ans in answers:
                resolved.append(str(ans))
        except Exception:
            pass

    if resolved:
        return _unique(resolved)

    try:
        infos = socket.getaddrinfo(target, None)
        for info in infos:
            sockaddr = info[4]
            if sockaddr:
                resolved.append(sockaddr[0])
    except Exception:
        return [target]

    return _unique(resolved) or [target]


def _lookup_ip(ip: str) -> dict:
    """Query ip-api for a single IP and return JSON payload."""
    resp = requests.get(_API.format(ip=ip), timeout=10)
    resp.raise_for_status()
    return resp.json()


def _is_cdn_or_proxy(data: dict) -> bool:
    """Heuristic CDN/proxy detection using ISP/Org/AS fields."""
    haystack = " ".join([
        str(data.get("isp", "")),
        str(data.get("org", "")),
        str(data.get("as", "")),
    ]).lower()

    markers = [
        "cloudflare",
        "akamai",
        "fastly",
        "cloudfront",
        "edgecast",
        "cdn",
        "incapsula",
        "sucuri",
    ]
    return any(marker in haystack for marker in markers)


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] IP Geolocation[/bold cyan]", expand=False))
    results = {}

    ips = _resolve_all(target)
    if len(ips) == 1:
        if ips[0] != target:
            console.print(f"  [dim]Resolved {target} → {ips[0]}[/dim]")
    else:
        console.print(f"  [dim]Resolved {target} → {', '.join(ips[:6])}{' ...' if len(ips) > 6 else ''}[/dim]")

    try:
        lookups = []
        for ip in ips:
            try:
                data = _lookup_ip(ip)
            except requests.RequestException:
                continue

            if data.get("status") == "success":
                lookups.append(data)

        if not lookups:
            console.print("  [red][!] Geolocation failed for resolved IPs.[/red]")
            console.print()
            return results

        primary = lookups[0]

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=20, no_wrap=True)
        table.add_column("Value", style="white")

        fields = {
            "IP Address":    primary.get("query", ips[0]),
            "Country":       f"{primary.get('country', '')} ({primary.get('countryCode', '')})",
            "Region":        primary.get("regionName", ""),
            "City":          primary.get("city", ""),
            "ZIP":           primary.get("zip", ""),
            "Coordinates":   f"{primary.get('lat', '')}, {primary.get('lon', '')}",
            "Timezone":      primary.get("timezone", ""),
            "ISP":           primary.get("isp", ""),
            "Organization":  primary.get("org", ""),
            "AS Number":     primary.get("as", ""),
        }

        for key, value in fields.items():
            if value and value.strip(" ,"):
                table.add_row(key, value)
                results[key] = value

        if len(lookups) > 1:
            endpoint_lines = []
            for item in lookups:
                endpoint_lines.append(
                    f"{item.get('query', '')} -> {item.get('country', 'N/A')}"
                    f"/{item.get('city', 'N/A')} ({item.get('org', 'N/A')})"
                )

            table.add_row("Resolved IPs", f"{len(lookups)} endpoints")
            results["Resolved IPs"] = ", ".join([i.get("query", "") for i in lookups if i.get("query")])
            results["Endpoint Summary"] = " | ".join(endpoint_lines[:6])

            console.print(table)
            console.print("  [bold yellow]Resolved Endpoint Locations:[/bold yellow]")
            for line in endpoint_lines:
                console.print(f"    [dim]-[/dim] {line}")
        else:
            console.print(table)

        if any(_is_cdn_or_proxy(item) for item in lookups):
            note = "Target appears behind CDN/proxy; geolocation likely shows edge POP, not origin server."
            console.print(f"\n  [bold yellow][!][/bold yellow] [yellow]{note}[/yellow]")
            results["Geo Note"] = note

    except requests.RequestException as e:
        console.print(f"  [red][!] Geolocation request failed: {e}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Geolocation error: {e}[/red]")

    console.print()
    return results
