"""
subdomain.py — Subdomain Discovery via Wordlist Brute-Force
Uses multi-threading to quickly resolve subdomains from a wordlist.
"""

import threading
import dns.resolver
from rich.console import Console
from rich.panel import Panel


def _check(sub: str, domain: str, found: list, lock: threading.Lock,
           console: Console, semaphore: threading.Semaphore) -> None:
    full = f"{sub}.{domain}"
    try:
        answers = dns.resolver.resolve(full, "A", lifetime=2)
        ips = [str(r) for r in answers]
        with lock:
            found.append({"subdomain": full, "ips": ips})
            console.print(
                f"  [bold green][+][/bold green] [cyan]{full}[/cyan] "
                f"[dim]→[/dim] [white]{', '.join(ips)}[/white]"
            )
    except Exception:
        pass
    finally:
        semaphore.release()


def run(target: str, wordlist_path: str, threads: int, console: Console) -> list:
    console.print(Panel("[bold cyan] Subdomain Discovery[/bold cyan]", expand=False))
    found = []
    lock = threading.Lock()

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        console.print(f"  [red][!] Wordlist not found: {wordlist_path}[/red]")
        console.print()
        return found

    console.print(f"  [dim]Scanning {len(subdomains)} entries with {threads} threads…[/dim]\n")

    semaphore = threading.Semaphore(threads)
    thread_list = []

    for sub in subdomains:
        semaphore.acquire()
        t = threading.Thread(target=_check, args=(sub, target, found, lock, console, semaphore), daemon=True)
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    if found:
        console.print(f"\n  [bold green][✓] {len(found)} subdomain(s) discovered[/bold green]")
    else:
        console.print("  [dim]No live subdomains found.[/dim]")

    console.print()
    return found
