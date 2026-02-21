import argparse
import socket
import sys
import threading
import concurrent.futures

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


def resolve_subdomain(subdomain):
    """Attempt to resolve a subdomain via DNS. Returns (subdomain, ip) or None."""
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except socket.gaierror:
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
    args = parser.parse_args()

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
        print()

    results = []
    progress = ProgressBar(len(subdomains)) if not quiet else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(resolve_subdomain, s): s for s in subdomains}
        for future in concurrent.futures.as_completed(futures):
            if progress:
                progress.update()
            result = future.result()
            sub = futures[future]
            if result:
                subdomain, ip = result
                if quiet:
                    print(f"{subdomain},{ip}")
                else:
                    if IS_TTY:
                        sys.stdout.write("\r" + " " * 70 + "\r")
                    print(green(f"[+] {subdomain}") + f" -> {ip}")
                results.append(result)
            elif args.verbose and not quiet:
                if IS_TTY:
                    sys.stdout.write("\r" + " " * 70 + "\r")
                print(red(f"[-] {sub}") + " - no resolution")
    if progress:
        progress.finish()

    if not quiet:
        print(yellow(f"\n[*] Found {len(results)} subdomain(s)"))

    if args.output and results:
        with open(args.output, "w") as f:
            for subdomain, ip in sorted(results):
                f.write(f"{subdomain},{ip}\n")
        if not quiet:
            print(yellow(f"[*] Results saved to {args.output}"))


if __name__ == "__main__":
    main()
