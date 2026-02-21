import argparse
import socket
import sys
import concurrent.futures


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
    args = parser.parse_args()

    try:
        prefixes = read_wordlist(args.wordlist)
    except FileNotFoundError:
        print(f"error: wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    subdomains = [f"{prefix}.{args.domain}" for prefix in prefixes]
    print(f"[*] Enumerating subdomains for {args.domain}")
    print(f"[*] Loaded {len(subdomains)} entries from {args.wordlist}")
    print(f"[*] Using {args.threads} threads")
    print()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(resolve_subdomain, s): s for s in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                subdomain, ip = result
                print(f"[+] {subdomain} -> {ip}")
                results.append(result)

    print(f"\n[*] Found {len(results)} subdomain(s)")

    if args.output and results:
        with open(args.output, "w") as f:
            for subdomain, ip in sorted(results):
                f.write(f"{subdomain},{ip}\n")
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    main()
