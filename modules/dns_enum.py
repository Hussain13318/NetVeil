"""
dns_enum.py — DNS Record Enumeration
Queries A, AAAA, MX, NS, TXT, CNAME, SOA records for a given domain.
"""

import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] DNS Record Enumeration[/bold cyan]", expand=False))
    results = {}

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(target, rtype, raise_on_no_answer=False)
            records = [str(r) for r in answers]
            if records:
                results[rtype] = records
                console.print(
                    f"  [bold yellow]{rtype:<6}[/bold yellow] [dim]→[/dim] [white]{chr(10).join(records)}[/white]"
                )
        except dns.resolver.NXDOMAIN:
            console.print("  [red][!] Domain does not exist (NXDOMAIN)[/red]")
            break
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException:
            pass
        except Exception:
            pass

    if not results:
        console.print("  [dim]No DNS records found.[/dim]")

    console.print()
    return results
