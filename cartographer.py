import argparse
import random
import socket
import string
import sys
import threading
import concurrent.futures

import re

import dns.resolver
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ANSI colors ---

USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    if USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text


def green(text):
    return _c("32", text)


def red(text):
    return _c("31", text)


def yellow(text):
    return _c("33", text)


def cyan(text):
    return _c("36", text)


def bold(text):
    return _c("1", text)


BANNER = r"""
                 __                                 __
  _______ ______/ /____  ____  ________ ____  ___  / /  ___ ____
 / __/ _ `/ __/ __/ __ \/ __ `/ __/ _ `/ _ \/ _ \/ _ \/ -_) __/
 \__/\_,_/_/  \__/\____/\_, /_/  \_,_/ .__/\___/_//_/\__/_/
                       /___/        /_/
"""


def print_banner():
    print(cyan(BANNER))


# --- Progress bar ---

IS_TTY = sys.stdout.isatty()


class ProgressBar:
    def __init__(self, total, width=30):
        self.total = total
        self.width = width
        self.done = 0
        self._lock = threading.Lock()

    def update(self):
        with self._lock:
            self.done += 1
            if not IS_TTY:
                return
            pct = self.done / self.total
            filled = int(self.width * pct)
            bar = "#" * filled + "-" * (self.width - filled)
            sys.stdout.write(f"\r  [{bar}] {self.done}/{self.total} ({pct:.0%})")
            sys.stdout.flush()

    def finish(self):
        if IS_TTY:
            sys.stdout.write("\r" + " " * (self.width + 30) + "\r")
            sys.stdout.flush()


# --- Core logic ---


def resolve_subdomain(subdomain, record_types=("A",)):
    """Resolve a subdomain for the given record types.

    Returns a list of (subdomain, rtype, value) tuples, or an empty list.
    """
    results = []
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(subdomain, rtype)
            for rdata in answers:
                results.append((subdomain, rtype, str(rdata)))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
    return results


def detect_wildcard(domain):
    """Check if the domain has a wildcard DNS record. Returns the wildcard IP or None."""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    try:
        ip = socket.gethostbyname(f"{rand}.{domain}")
        return ip
    except socket.gaierror:
        return None


def probe_http(subdomain, timeout=3):
    """Probe HTTP/HTTPS for a subdomain. Returns (status_code, title) or None."""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{subdomain}",
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            title = ""
            match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:4096], re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
            return (resp.status_code, title)
        except requests.RequestException:
            continue
    return None


def read_wordlist(filepath):
    """Read subdomain prefixes from a wordlist file, one per line."""
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="cartographer - simple subdomain enumeration tool"
    )
    parser.add_argument("domain", help="target domain (e.g. example.com)")
    parser.add_argument(
        "-w",
        "--wordlist",
        default="wordlist.txt",
        help="path to wordlist file (default: wordlist.txt)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "-o", "--output", help="write results to a file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="show failed lookups"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="minimal output, only print subdomain,ip lines (for piping)"
    )
    parser.add_argument(
        "-r", "--records", default="A",
        help="comma-separated DNS record types to query (default: A). e.g. A,AAAA,CNAME,MX"
    )
    parser.add_argument(
        "--probe", action="store_true",
        help="probe HTTP/HTTPS on discovered subdomains and show status code + title"
    )
    args = parser.parse_args()

    record_types = [r.strip().upper() for r in args.records.split(",")]

    quiet = args.quiet

    if not quiet:
        print_banner()

    try:
        prefixes = read_wordlist(args.wordlist)
    except FileNotFoundError:
        print(red(f"[!] error: wordlist not found: {args.wordlist}"), file=sys.stderr)
        sys.exit(1)

    subdomains = [f"{prefix}.{args.domain}" for prefix in prefixes]
    if not quiet:
        print(yellow(f"[*] Enumerating subdomains for {bold(args.domain)}"))
        print(yellow(f"[*] Loaded {len(subdomains)} entries from {args.wordlist}"))
        print(yellow(f"[*] Using {args.threads} threads"))
        print(yellow(f"[*] Record types: {', '.join(record_types)}"))

    wildcard_ip = detect_wildcard(args.domain)
    if wildcard_ip and not quiet:
        print(yellow(f"[*] Wildcard detected: *.{args.domain} -> {wildcard_ip} (filtering false positives)"))

    if not quiet:
        print()

    results = []
    progress = ProgressBar(len(subdomains)) if not quiet else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(resolve_subdomain, s, record_types): s
            for s in subdomains
        }
        for future in concurrent.futures.as_completed(futures):
            if progress:
                progress.update()
            records = future.result()
            sub = futures[future]
            if records:
                for subdomain, rtype, value in records:
                    if wildcard_ip and rtype == "A" and value == wildcard_ip:
                        continue
                    if quiet:
                        print(f"{subdomain},{rtype},{value}")
                    else:
                        if IS_TTY:
                            sys.stdout.write("\r" + " " * 70 + "\r")
                        print(green(f"[+] {subdomain}") + f" {rtype} -> {value}")
                    results.append((subdomain, rtype, value))
            elif args.verbose and not quiet:
                if IS_TTY:
                    sys.stdout.write("\r" + " " * 70 + "\r")
                print(red(f"[-] {sub}") + " - no resolution")
    if progress:
        progress.finish()

    if not quiet:
        print(yellow(f"\n[*] Found {len(results)} record(s)"))

    # HTTP probing
    http_results = {}
    if args.probe and results:
        unique_subs = sorted(set(sub for sub, _, _ in results))
        if not quiet:
            print(yellow(f"\n[*] Probing HTTP/HTTPS on {len(unique_subs)} subdomain(s)..."))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            probe_futures = {executor.submit(probe_http, s): s for s in unique_subs}
            for future in concurrent.futures.as_completed(probe_futures):
                sub = probe_futures[future]
                probe = future.result()
                if probe:
                    status, title = probe
                    http_results[sub] = {"status": status, "title": title}
                    title_str = f" ({title})" if title else ""
                    if quiet:
                        print(f"{sub},HTTP,{status}{title_str}")
                    else:
                        if IS_TTY:
                            sys.stdout.write("\r" + " " * 70 + "\r")
                        print(green(f"[+] {sub}") + f" -> {status}{title_str}")

    if args.output and results:
        with open(args.output, "w") as f:
            for subdomain, rtype, value in sorted(results):
                extra = ""
                if subdomain in http_results:
                    h = http_results[subdomain]
                    extra = f",{h['status']},{h['title']}"
                f.write(f"{subdomain},{rtype},{value}{extra}\n")
        if not quiet:
            print(yellow(f"[*] Results saved to {args.output}"))


if __name__ == "__main__":
    main()
