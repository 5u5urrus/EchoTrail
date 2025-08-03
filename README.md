# EchoTrail - Track Hidden Paths Through Time

**EchoTrail** is a best of its kind, fast and precise Python tool that mines the Wayback Machine for archived URLs, extracts unique parameterized paths, filters noise, and verifies which URLs are still live. It’s designed for red teamers, bug bounty hunters, and OSINT professionals.

Developed by Vahe Demirkhanyan | [hackvector.io](https://hackvector.io)

---

## Features

- Smart deduplication based on parameter structure
- Subdomain-aware filtering
- Optional blacklist for static file extensions (e.g., `.jpg`, `.css`)
- Live URL verification with HTTP status codes
- Includes or excludes dead URLs
- Asynchronous and concurrency-safe
- Outputs results to file or screen
- Root domain DNS check and header preview

---

## Installation

```bash
git clone https://github.com/yourname/echotrail.git
cd echotrail
pip install -r requirements.txt
```

Requirements:
- Python 3.7+
- `aiohttp`, `colorama`, `requests`

---

## Usage

```bash
python echotrail.py -t example.com
```

### Options

| Option             | Description                                                  |
|-------------------|--------------------------------------------------------------|
| `-t, --domain`     | Target domain (required)                                     |
| `-e, --exclude`    | Comma-separated blacklist of file extensions (e.g. `.jpg,.css`) |
| `-o, --output`     | Write live URLs to file                                      |
| `-v, --verify`     | Show HTTP status codes with live URLs                        |
| `-a, --all`        | Include dead URLs (404, timeouts, etc.)                      |
| `-s, --subdomains` | Include subdomains (e.g. `blog.example.com`)                 |

### Example

```bash
python echotrail.py -t target.com -e .jpg,.png,.svg -o output.txt -v -s
```

---

## Output Example

```
[+] Searching Wayback for target.com...
[+] URLs found: 2749
[+] Live URLs:
[+] https://target.com/item.php?id=7&user=2 - Status: 200
[+] https://sub.target.com/info.php?lang=en - Status: 302
[*] Total unique URLs processed: 182
[*] Live URLs (not 404): 97
```

---

## How It Works

EchoTrail queries the Wayback Machine's CDX API, extracts archived URLs, and:

- Normalizes the parameter key order
- Deduplicates based on parameter structure (not values)
- Filters out static assets (optional)
- Validates which URLs are still accessible
- Outputs clean, high-signal endpoints for recon

---

## Use Cases

- Bug bounty reconnaissance
- Open-source intelligence (OSINT)
- Discovering forgotten or legacy endpoints
- Building parameter wordlists

---

## Author

Vahe Demirkhanyan  
Website: [https://hackvector.io](https://hackvector.io)  

---

## Disclaimer

This tool is intended for **educational** and **authorized security testing** only. Do not use it against systems without permission.

---

## License

MIT License
