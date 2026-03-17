"""
ssl_check.py — SSL/TLS Certificate Analysis
Inspects the certificate of a domain on port 443.
"""

import ssl
import socket
import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def run(target: str, console: Console) -> dict:
    console.print(Panel("[bold cyan] SSL Certificate Analysis[/bold cyan]", expand=False))
    results = {}

    # Strip protocol/path so we get a clean hostname
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter", "")

        # Expiry status
        expiry_tag_rich  = ""   # Rich-formatted (terminal only)
        expiry_tag_plain = ""   # Plain text (HTML report)
        if not_after:
            try:
                expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_dt - datetime.datetime.utcnow()).days
                if days_left < 0:
                    expiry_tag_rich  = " [bold red][ EXPIRED ][/bold red]"
                    expiry_tag_plain = " [ EXPIRED ]"
                elif days_left < 30:
                    expiry_tag_rich  = f" [bold yellow][ Expires in {days_left} days ][/bold yellow]"
                    expiry_tag_plain = f" [ Expires in {days_left} days ]"
                else:
                    expiry_tag_rich  = f" [bold green][ {days_left} days remaining ][/bold green]"
                    expiry_tag_plain = f" [ {days_left} days remaining ]"
            except ValueError:
                pass

        # Subject Alternative Names
        sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold yellow", width=22, no_wrap=True)
        table.add_column("Value", style="white")

        rows = {
            "Common Name":      subject.get("commonName", "N/A"),
            "Organization":     subject.get("organizationName", ""),
            "Issued By":        issuer.get("organizationName", "N/A"),
            "Issuer CN":        issuer.get("commonName", ""),
            "Valid From":       not_before,
            "Valid Until":      not_after + expiry_tag_rich,
            "TLS Version":      ssock.version() if False else cert.get("version", ""),
            "Serial Number":    str(cert.get("serialNumber", "")),
            "Alt Names (SANs)": ", ".join(sans[:8]) + (" …" if len(sans) > 8 else ""),
        }
        # Plain-text version used by the HTML reporter (no Rich markup)
        rows_plain = dict(rows)
        rows_plain["Valid Until"] = not_after + expiry_tag_plain

        # Re-open briefly just to get TLS version
        try:
            with socket.create_connection((hostname, 443), timeout=5) as s2:
                with ctx.wrap_socket(s2, server_hostname=hostname) as ss2:
                    rows["TLS Version"] = ss2.version()
        except Exception:
            pass

        for key, value in rows.items():
            if value:
                table.add_row(key, str(value))
                # Store plain-text version so HTML report has no Rich tags
                results[key] = str(rows_plain.get(key, value))

        console.print(table)

    except ssl.SSLCertVerificationError as e:
        console.print(f"  [red][!] Certificate verification failed: {e}[/red]")
    except ConnectionRefusedError:
        console.print(f"  [red][!] Port 443 closed on {hostname}[/red]")
    except socket.timeout:
        console.print(f"  [red][!] Connection timed out for {hostname}[/red]")
    except Exception as e:
        console.print(f"  [red][!] SSL check failed: {e}[/red]")

    console.print()
    return results
