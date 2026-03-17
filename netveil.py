#!/usr/bin/env python3
"""
NetVeil - OSINT & Threat Recon Intelligence Tool
-------------------------------------------------
Author  : [Your Name]
GitHub  : https://github.com/yourusername/NetVeil
Version : 1.0
"""

import argparse
import os
import sys
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

from modules import dns_enum, whois_lookup, subdomain, geo_ip, ssl_check, virustotal, shodan_scan, reporter

console = Console()

BANNER = r"""
[bold cyan]
  _   _      _  __     __   _ _ 
 | \ | | ___| |_\ \   / /__(_) |
 |  \| |/ _ \ __\ \ / / _ \ | |
 | |\  |  __/ |_ \ V /  __/ | |
 |_| \_|\___|\__| \_/ \___|_|_|
[/bold cyan]
[bold white]      OSINT & Threat Recon Intelligence Tool[/bold white]
[dim]      Version 1.0  |  github.com/yourusername/NetVeil[/dim]
"""


def main():
    parser = argparse.ArgumentParser(
        prog="netveil",
        description="NetVeil — OSINT & Threat Recon Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netveil.py -t example.com --full
  python netveil.py -t example.com --dns --whois --ssl
  python netveil.py -t 8.8.8.8 --geo --shodan
  python netveil.py -t example.com --full --report
        """,
    )

    parser.add_argument("-t", "--target",    required=True,  help="Target domain or IP address")
    parser.add_argument("--dns",             action="store_true", help="DNS record enumeration")
    parser.add_argument("--whois",           action="store_true", help="WHOIS lookup")
    parser.add_argument("--subdomain",       action="store_true", help="Subdomain discovery")
    parser.add_argument("--geo",             action="store_true", help="IP geolocation")
    parser.add_argument("--ssl",             action="store_true", help="SSL certificate analysis")
    parser.add_argument("--vt",              action="store_true", help="VirusTotal reputation check")
    parser.add_argument("--shodan",          action="store_true", help="Shodan port/service intel")
    parser.add_argument("--full",            action="store_true", help="Run ALL modules")
    parser.add_argument("--report",          action="store_true", help="Save HTML report")
    parser.add_argument("--threads", type=int, default=15,
                        help="Threads for subdomain scan (default: 15)")
    parser.add_argument("--wordlist",  default=os.path.join(os.path.dirname(__file__), "wordlists", "subdomains.txt"),
                        help="Wordlist path for subdomain discovery")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    console.print(BANNER)
    console.rule("[bold cyan]Scan Started[/bold cyan]")
    console.print(f"  [bold green][*] Target   :[/bold green] [bold white]{args.target}[/bold white]")
    console.print(f"  [bold green][*] Timestamp:[/bold green] [bold white]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold white]")
    console.rule()
    console.print()

    results = {
        "target": args.target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    run_all = args.full

    if run_all or args.dns:
        results["dns"] = dns_enum.run(args.target, console)

    if run_all or args.whois:
        results["whois"] = whois_lookup.run(args.target, console)

    if run_all or args.subdomain:
        results["subdomains"] = subdomain.run(args.target, args.wordlist, args.threads, console)

    if run_all or args.geo:
        results["geo"] = geo_ip.run(args.target, console)

    if run_all or args.ssl:
        results["ssl"] = ssl_check.run(args.target, console)

    if run_all or args.vt:
        results["virustotal"] = virustotal.run(args.target, console)

    if run_all or args.shodan:
        results["shodan"] = shodan_scan.run(args.target, console)

    if args.report:
        report_path = reporter.generate(results, args.target)
        console.print(f"\n  [bold green][✓] HTML Report saved → [/bold green][cyan]{report_path}[/cyan]")

    console.rule()
    console.print(f"  [bold green][✓] Scan finished at {datetime.now().strftime('%H:%M:%S')}[/bold green]")
    console.rule()


if __name__ == "__main__":
    main()
