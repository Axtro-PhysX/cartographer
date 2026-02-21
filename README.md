# cartographer

Subdomain enumeration tool with multithreaded DNS resolution, wildcard detection, HTTP probing, and recursive scanning.

## Setup

```
pip install -r requirements.txt
```

## Usage

```
python3 cartographer.py <domain> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-w` | Path to wordlist file | `wordlist.txt` |
| `-t` | Number of threads | `10` |
| `-o` | Output results to file | — |
| `-v` | Show failed lookups | off |
| `-q` | Quiet mode — bare CSV output for piping | off |
| `-r` | DNS record types (comma-separated) | `A` |
| `--probe` | Probe HTTP/HTTPS, show status code + page title | off |
| `--delay` | Seconds to sleep between lookups per thread | `0` |
| `--json` | Output results as JSON | off |
| `--recursive` | Recursively scan discovered subdomains | off |
| `--depth` | Max recursion depth | `1` |

### Examples

```
python3 cartographer.py example.com
python3 cartographer.py example.com -w custom_wordlist.txt -t 50
python3 cartographer.py example.com -o results.csv
python3 cartographer.py example.com -r A,AAAA,CNAME,MX
python3 cartographer.py example.com --probe
python3 cartographer.py example.com --json --probe
python3 cartographer.py example.com --recursive --depth 2
python3 cartographer.py example.com -q | wc -l
python3 cartographer.py example.com --delay 0.5 -t 5
```
