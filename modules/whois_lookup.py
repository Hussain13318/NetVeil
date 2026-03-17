"""
whois_lookup.py — WHOIS Domain Lookup
Retrieves registrar, registration dates, name servers, and contact info.
"""

import whois
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def _as_str(value) -> str:
    """Safely convert a WHOIS field (may be list or datetime) to a readable string."""
    if value is None:
        return ""
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value).strip()


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] WHOIS Lookup[/bold cyan]", expand=False))
    results = {}

    try:
        w = whois.whois(target)

        fields = {
            "Domain Name":    _as_str(w.domain_name),
            "Registrar":      _as_str(w.registrar),
            "Creation Date":  _as_str(w.creation_date),
            "Expiry Date":    _as_str(w.expiration_date),
            "Updated Date":   _as_str(w.updated_date),
            "Name Servers":   ", ".join(w.name_servers) if isinstance(w.name_servers, list) else _as_str(w.name_servers),
            "Status":         _as_str(w.status),
            "Registrant Org": _as_str(w.org),
            "Country":        _as_str(w.country),
            "Emails":         _as_str(w.emails),
        }

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=20, no_wrap=True)
        table.add_column("Value", style="white")

        for key, value in fields.items():
            if value:
                table.add_row(key, value)
                results[key] = value

        if results:
            console.print(table)
        else:
            console.print("  [dim]No WHOIS data returned.[/dim]")

    except Exception as e:
        console.print(f"  [red][!] WHOIS failed: {e}[/red]")

    console.print()
    return results
