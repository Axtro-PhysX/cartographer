# cartographer

Simple subdomain enumeration tool. Uses multithreaded DNS resolution to check subdomains from a wordlist against a target domain.

No dependencies — standard library only.

## Usage

```
python3 main.py <domain> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-w` | Path to wordlist file | `wordlist.txt` |
| `-t` | Number of threads | `10` |
| `-o` | Output results to file (CSV) | — |

### Examples

```
python3 main.py example.com
python3 main.py example.com -w custom_wordlist.txt -t 50
python3 main.py example.com -o results.csv
```
