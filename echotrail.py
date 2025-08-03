import argparse
import asyncio
import aiohttp
from aiohttp import ClientConnectorError, ClientResponseError, ServerTimeoutError
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl, urlunparse
from colorama import Fore, Style
import socket

# Banner

print(Fore.GREEN + "\n" + "=" * 60)
print(Fore.GREEN + "E C H O T R A I L - Track Hidden Paths Through Time")
print(Fore.GREEN + "-" * 60)
print(Fore.GREEN + "Author: Vahe Demirkhanyan | hackvector.io")
print("=" * 60 + Style.RESET_ALL + "\n")


# Constants
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
WAYBACK_URL_TEMPLATE = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"

# Colors helper
class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL

def should_skip_url_path_only(url, blacklist):
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in blacklist)

def normalize_netloc(netloc):
    return netloc.split(':')[0].lower()

def param_names_key(parsed):
    names = sorted(parse_qs(parsed.query).keys())
    key_qs = "&".join(names)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', key_qs, ''))

def matches_domain(netloc, domain_normalized, allow_subdomains):
    """
    If allow_subdomains is False: only domain_normalized and www.domain_normalized pass.
    If True: domain_normalized and any real subdomain (*.domain_normalized) pass.
    """
    if netloc == domain_normalized or netloc == f"www.{domain_normalized}":
        return True
    if allow_subdomains:
        return netloc.endswith(f".{domain_normalized}")
    return False

async def fetch_wayback_urls(session, domain):
    print(f"{Colors.CYAN}[+] Searching Wayback for {domain}...{Colors.RESET}")
    url = WAYBACK_URL_TEMPLATE.format(domain=domain)
    backoff = 1
    for attempt in range(3):
        try:
            async with session.get(url, timeout=20) as resp:
                data = await resp.json(content_type=None)
                urls = []
                for entry in data[1:]:
                    if entry and isinstance(entry, list) and entry[0]:
                        urls.append(entry[0])
                print(f"{Colors.GREEN}[+] URLs found: {len(urls)}{Colors.RESET}")
                return urls
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Wayback error for {domain} (attempt {attempt+1}): {e}{Colors.RESET}")
            await asyncio.sleep(backoff)
            backoff *= 2
    print(f"{Colors.RED}[!] Failed to get Wayback URLs for {domain} after retries.{Colors.RESET}")
    return []

async def verify_url(url, args, session, live_urls, seen_urls, seen_param_keys, blacklist, domain_normalized):
    try:
        parsed = urlparse(url)
        netloc = normalize_netloc(parsed.netloc)

        if not matches_domain(netloc, domain_normalized, args.subdomains):
            return
        if not parsed.query:
            return

        if should_skip_url_path_only(url, blacklist):
            return

        key = param_names_key(parsed)
        if key in seen_param_keys:
            return
        seen_param_keys.add(key)

        full_qs = urlencode(sorted(parse_qsl(parsed.query)), doseq=True)
        full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', full_qs, ''))

        if full_url in seen_urls:
            return
        seen_urls.add(full_url)

        status = None
        for attempt in range(3):
            try:
                async with session.get(full_url, timeout=15, allow_redirects=False) as resp:
                    status = resp.status
                    break
            except (ClientConnectorError, ServerTimeoutError, ClientResponseError, asyncio.TimeoutError) as e:
                if args.all:
                    print(f"{Colors.YELLOW}[!] Error fetching {full_url} (attempt {attempt+1}): {e}{Colors.RESET}")
                await asyncio.sleep(1 * (2 ** attempt))

        is_live = (status is not None and status != 404)
        if is_live:
            live_urls.add(full_url)
            if args.verify:
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {full_url} - Status: {status}")
            else:
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {full_url}")
        else:
            if args.all:
                marker = f"[{Fore.YELLOW}~{Style.RESET_ALL}]"
                if args.verify:
                    code_display = status if status is not None else "ERR"
                    print(f"{marker} {full_url} - Invalid status: {code_display}")
                else:
                    print(f"{marker} {full_url}")
            # otherwise skip dead silently
    except Exception as e:
        if args.all:
            print(f"{Colors.YELLOW}[!] Exception in verify_url for {url}: {e}{Colors.RESET}")

async def main_async(args, blacklist, live_urls, seen_urls, seen_param_keys):
    domain_normalized = args.domain.lower()
    connector = aiohttp.TCPConnector(ssl=False, limit_per_host=10)
    headers = {'User-Agent': USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
        urls_wayback = await fetch_wayback_urls(session, args.domain)
        if not urls_wayback:
            return

        sem = asyncio.Semaphore(10)
        async def wrapped(u):
            async with sem:
                await verify_url(u, args, session, live_urls, seen_urls, seen_param_keys, blacklist, domain_normalized)

        await asyncio.gather(*(wrapped(u) for u in set(urls_wayback)))

def fetch_root_headers_sync(domain):
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})
    try:
        # DNS pre-check
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"{Colors.YELLOW}[!] DNS resolution failed for {domain}, skipping root header fetch.{Colors.RESET}")
            return "", {}, {}

        for scheme in ("http", "https"):
            try:
                resp = session.get(f"{scheme}://{domain}", timeout=10, verify=False)
                return resp.text, resp.status_code, resp.headers
            except requests.exceptions.RequestException:
                continue
        print(f"{Colors.YELLOW}[!] No reachable scheme for {domain} (http/https).{Colors.RESET}")
        return "", {}, {}
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error fetching headers for {domain}: {e}{Colors.RESET}")
        return "", {}, {}

def main():
    parser = argparse.ArgumentParser(description='EchoTrail - gather unique archived URLs from Wayback')
    parser.add_argument('-t', '--domain', type=str, required=True, help='Domain to search')
    parser.add_argument('-e', '--exclude', type=str, help='Extensions to exclude (path only), comma-separated (e.g., .jpg,.png)')
    parser.add_argument('-o', '--output', type=str, help='File to export live URLs')
    parser.add_argument('-v', '--verify', action='store_true', help='Show status codes next to URLs')
    parser.add_argument('-a', '--all', action='store_true', help='Include dead URLs (404/errors) in output')
    parser.add_argument('-s', '--subdomains', action='store_true', help='Also include real subdomains (*.domain)')

    args = parser.parse_args()

    if args.verify and not args.output:
        print(f"{Colors.YELLOW}[!] Warning: used -v without -o; output will appear on screen but not saved.{Colors.RESET}")

    exclude_set = set()
    if args.exclude:
        exclude_set = {ext.strip().lower() for ext in args.exclude.split(',') if ext.strip()}

    if exclude_set:
        print(f"{Colors.YELLOW}[!] Excluding URLs with these extensions (path only): {exclude_set}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] No extensions will be excluded{Colors.RESET}")

    _, _, headers = fetch_root_headers_sync(args.domain)
    print(f"\n{Colors.GREEN}[*] Domain headers: {headers}{Colors.RESET}\n")

    live_urls = set()
    seen_urls = set()
    seen_param_keys = set()

    try:
        asyncio.run(main_async(args, exclude_set, live_urls, seen_urls, seen_param_keys))
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}\n[!] Cancelled by user.{Colors.RESET}")

    print(f"\n{Colors.YELLOW}[*] Total unique URLs processed: {len(seen_urls)}{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Live URLs (not 404): {len(live_urls)}{Colors.RESET}")
    if args.output:
        try:
            with open(args.output, "a", encoding="utf-8") as f:
                for u in sorted(live_urls):
                    f.write(f"{u}\n")
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error writing final output file: {e}{Colors.RESET}")

if __name__ == '__main__':
    main()
