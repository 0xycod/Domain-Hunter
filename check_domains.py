#!/usr/bin/env python3
"""
check_domains.py

Just run:
    python check_domains.py

...and you'll land in a colorful menu that can build a config.json for
you (name list, proxy list, extensions, concurrency, etc.) and run
checks with a live dashboard. After first setup you can also just do:

    python check_domains.py --run

Requirements:
    pip install aiohttp python-whois rich pyfiglet
"""

import asyncio
import itertools
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import aiohttp
except ImportError:
    print("Missing dependency 'aiohttp'. Install it with:\n    pip install aiohttp")
    sys.exit(1)

try:
    import whois as whois_lib  # pip install python-whois
    HAVE_WHOIS = True
except ImportError:
    HAVE_WHOIS = False

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
    from rich.prompt import Prompt, IntPrompt, FloatPrompt, Confirm
    from rich.rule import Rule
    from rich import box
except ImportError:
    print("Missing dependency 'rich'. Install it with:\n    pip install rich")
    sys.exit(1)

try:
    import pyfiglet
    HAVE_FIGLET = True
except ImportError:
    HAVE_FIGLET = False

console = Console()

# --------------------------------------------------------------------------
# Palette — warm light-orange theme
# --------------------------------------------------------------------------

C_PRIMARY = "#ff9800"    # orange
C_PRIMARY2 = "#ffb74d"   # light orange / amber
C_ACCENT = "#ffd180"     # pale gold accent
C_GOOD = "#00e676"       # green (available domains)
C_BAD = "#ff5252"        # red (taken)
C_MUTED = "#9a9a9a"      # gray
C_WARN = "#fff176"       # soft yellow (distinct from primary orange)
C_TEXT = "#f5f0e8"

# Hand-drawn "search / hunter" badge — not a text font, a small pixel-art icon
LOGO_ART = [
    r"        ▄▄▄▄▄▄▄▄▄▄",
    r"      ▄██████████████▄",
    r"    ▄██▀▀▀▀▀▀▀▀▀▀▀▀▀▀██▄",
    r"   ██▀     ▄▄▄▄▄▄     ▀██",
    r"  ██     ▄█▀▀▀▀▀▀█▄     ██",
    r"  ██    ██   ●●   ██    ██",
    r"  ██    ██   ●●   ██    ██",
    r"  ██     ▀█▄▄▄▄▄▄█▀     ██",
    r"   ██▄     ▀▀▀▀▀▀     ▄██",
    r"    ▀██▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▀",
    r"      ▀██▄▄▄▄▄▄▄▄▄▄██▀",
    r"        ▀▀██▄▄▄▄██▀▀",
    r"             ▀▀▀▀",
    r"              ▀█▄",
    r"               ▀█▄",
    r"                ▀█▄",
]


# --------------------------------------------------------------------------
# Constants / paths
# --------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
RDAP_CACHE_PATH = SCRIPT_DIR / "rdap_bootstrap_cache.json"
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_CACHE_MAX_AGE_DAYS = 30

FALLBACK_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.identitydigital.services/rdap/",
    "biz": "https://rdap.nic.biz/",
    "co": "https://rdap.nic.co/",
    "me": "https://rdap.nic.me/",
    "us": "https://rdap.nic.us/",
    "xyz": "https://rdap.centralnic.com/xyz/",
    "dev": "https://pubapi.registry.google/rdap/",
    "app": "https://pubapi.registry.google/rdap/",
    "io": "https://rdap.nic.io/",
}

DEFAULT_CONFIG = {
    "namelist_file": "names.txt",
    "proxy_list_file": "",
    "extensions": [".com"],
    "output_dir": "results",
    "max_concurrency": 30,
    "request_timeout_seconds": 8,
    "delay_between_requests": 0.0,
    "retries": 2,
}


# --------------------------------------------------------------------------
# Visual chrome: banner, gradient text, panels
# --------------------------------------------------------------------------

def gradient_text(s: str, start_hex: str, end_hex: str) -> Text:
    def hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    r1, g1, b1 = hex_to_rgb(start_hex)
    r2, g2, b2 = hex_to_rgb(end_hex)
    n = max(len(s) - 1, 1)
    text = Text()
    for i, ch in enumerate(s):
        t = i / n
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        text.append(ch, style=f"bold #{r:02x}{g:02x}{b:02x}")
    return text


def gradient_lines(lines: list, start_hex: str, end_hex: str) -> Group:
    """Vertical gradient: colors each whole line, interpolating top -> bottom."""
    def hex_to_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    r1, g1, b1 = hex_to_rgb(start_hex)
    r2, g2, b2 = hex_to_rgb(end_hex)
    n = max(len(lines) - 1, 1)
    texts = []
    for i, line in enumerate(lines):
        t = i / n
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        texts.append(Text(line, style=f"bold #{r:02x}{g:02x}{b:02x}"))
    return Group(*texts)


def print_banner(subtitle: str = "premium domain availability scanner"):
    console.clear()
    size = console.size
    full_banner_fits = size.width >= 92 and size.height >= 34

    if full_banner_fits:
        logo = gradient_lines(LOGO_ART, C_ACCENT, C_PRIMARY)
        console.print(Align.center(logo))

        if HAVE_FIGLET:
            art = pyfiglet.figlet_format("DOMAIN HUNTER", font="small")
        else:
            art = "DOMAIN HUNTER"
        lines = [line for line in art.split("\n") if line.strip()]
        wordmark = Group(*[gradient_text(line, C_PRIMARY2, C_PRIMARY) for line in lines])
        console.print(Align.center(wordmark))
        console.print(Align.center(Text(subtitle, style=f"italic {C_MUTED}")))
        console.print()
    else:
        # Compact header for smaller terminal windows: always fits, no scrolling.
        header = Text.assemble(("🔎  ", "bold"), ("DOMAIN HUNTER", f"bold {C_PRIMARY}"))
        badge = Panel(
            Align.center(Group(Align.center(header), Align.center(Text(subtitle, style=f"italic {C_MUTED}")))),
            border_style=C_PRIMARY, box=box.HEAVY, padding=(0, 2),
        )
        console.print(badge)
        console.print()


def section_rule(title: str, style: str = C_PRIMARY):
    console.print(Rule(Text(f" {title} ", style=f"bold {style}"), style=style))


def footer_bar(text: str):
    console.print(Align.center(Text(text, style=f"dim {C_MUTED}")))


# --------------------------------------------------------------------------
# Config handling
# --------------------------------------------------------------------------

def load_config(path: Path = None) -> dict:
    path = path or CONFIG_PATH
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    merged = {**DEFAULT_CONFIG, **data}
    return merged


def save_config(config: dict, path: Path = None):
    path = path or CONFIG_PATH
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    console.print(Align.center(Panel(f"[bold {C_GOOD}]✔ Saved[/] configuration to [bold]{path}[/]",
                                      border_style=C_GOOD, box=box.DOUBLE, padding=(0, 3))))


def config_wizard(existing: dict = None) -> dict:
    base = existing or DEFAULT_CONFIG
    print_banner("configuration wizard")
    console.print(Align.center(Rule(Text(" step through each setting — press enter to keep the default ",
                                          style=f"italic {C_MUTED}"), style=C_PRIMARY)))
    console.print()

    namelist_file = Prompt.ask(f"[{C_PRIMARY2}]Name list file[/] [dim](one name per line)[/]",
                                default=base["namelist_file"])

    proxy_list_file = Prompt.ask(
        f"[{C_PRIMARY2}]Proxy list file[/] [dim](one http(s) proxy per line, blank = none)[/]",
        default=base.get("proxy_list_file", ""),
    )

    ext_default = ",".join(base["extensions"])
    ext_raw = Prompt.ask(f"[{C_PRIMARY2}]Extensions[/] [dim](comma separated, e.g. .com,.net,.io)[/]",
                          default=ext_default)
    extensions = []
    for e in ext_raw.split(","):
        e = e.strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        extensions.append(e)
    if not extensions:
        extensions = [".com"]

    output_dir = Prompt.ask(f"[{C_PRIMARY2}]Output directory[/]", default=base["output_dir"])

    max_concurrency = IntPrompt.ask(f"[{C_PRIMARY2}]Max concurrent lookups[/] [dim](higher = faster)[/]",
                                     default=base["max_concurrency"])
    request_timeout = FloatPrompt.ask(f"[{C_PRIMARY2}]Per-request timeout (s)[/]",
                                       default=base["request_timeout_seconds"])
    delay = FloatPrompt.ask(f"[{C_PRIMARY2}]Delay between requests (s)[/] [dim](0 = none)[/]",
                             default=base["delay_between_requests"])
    retries = IntPrompt.ask(f"[{C_PRIMARY2}]Retries on rate-limit/errors[/]", default=base["retries"])

    config = {
        "namelist_file": namelist_file,
        "proxy_list_file": proxy_list_file,
        "extensions": extensions,
        "output_dir": output_dir,
        "max_concurrency": max_concurrency,
        "request_timeout_seconds": request_timeout,
        "delay_between_requests": delay,
        "retries": retries,
    }

    console.print()
    save_config(config)
    console.print()
    footer_bar("press enter to continue")
    console.input("")
    return config


# --------------------------------------------------------------------------
# Input file loading
# --------------------------------------------------------------------------

def normalize_name(raw: str) -> str:
    name = raw.strip().lower().replace(" ", "")
    name = re.sub(r"\.(com|net|org|io|co|info|biz|me|us|xyz|dev|app)$", "", name)
    name = re.sub(r"[^a-z0-9\-]", "", name)
    return name


def load_names(path: str) -> list:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Name list file not found: {path}")
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_proxies(path: str) -> list:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        console.print(f"[{C_WARN}]Warning:[/] proxy list file '{path}' not found. Continuing without proxies.")
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


# --------------------------------------------------------------------------
# RDAP bootstrap (TLD -> RDAP server) with local caching
# --------------------------------------------------------------------------

async def fetch_rdap_bootstrap(session: aiohttp.ClientSession) -> dict:
    if RDAP_CACHE_PATH.exists():
        try:
            cached = json.loads(RDAP_CACHE_PATH.read_text(encoding="utf-8"))
            age_days = (time.time() - cached.get("fetched_at", 0)) / 86400
            if age_days < RDAP_CACHE_MAX_AGE_DAYS and cached.get("map"):
                return cached["map"]
        except Exception:
            pass

    tld_map = {}
    try:
        async with session.get(IANA_BOOTSTRAP_URL, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json(content_type=None)
        for entry in data.get("services", []):
            tlds, urls = entry[0], entry[1]
            if not urls:
                continue
            url = urls[0]
            if not url.endswith("/"):
                url += "/"
            for tld in tlds:
                tld_map[tld.lower()] = url
        RDAP_CACHE_PATH.write_text(
            json.dumps({"fetched_at": time.time(), "map": tld_map}, indent=2), encoding="utf-8"
        )
        return tld_map
    except Exception as e:
        console.print(f"[{C_WARN}]Warning:[/] could not fetch live RDAP bootstrap ({e}). Using built-in fallback map.")
        return dict(FALLBACK_RDAP)


# --------------------------------------------------------------------------
# Domain checking
# --------------------------------------------------------------------------

# The 'whois' package sometimes prints raw socket errors straight to
# stdout/stderr on failure (e.g. "Error trying to connect to socket:
# closing socket - [Errno 11001] getaddrinfo failed" on Windows when a
# WHOIS server can't be resolved). Running it in a subprocess means that
# noise goes into a pipe we fully control instead of leaking onto the
# user's terminal and corrupting the live dashboard.
_WHOIS_SUBPROCESS_CODE = (
    "import sys, json\n"
    "try:\n"
    "    import whois\n"
    "    w = whois.whois(sys.argv[1])\n"
    "    registered = bool(w and (w.domain_name or w.creation_date))\n"
    "    print('@@RESULT@@' + json.dumps({'ok': True, 'registered': registered}))\n"
    "except Exception as e:\n"
    "    print('@@RESULT@@' + json.dumps({'ok': False, 'error': str(e)}))\n"
)


async def check_via_whois(domain: str, timeout: float) -> tuple:
    if not HAVE_WHOIS:
        raise RuntimeError("python-whois not installed")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", _WHOIS_SUBPROCESS_CODE, domain,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,  # swallow any noisy library prints
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max(timeout * 2, 10))
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()  # reap the process so its transport doesn't warn at shutdown
        except ProcessLookupError:
            pass
        raise RuntimeError("whois lookup timed out")

    result_line = None
    for line in stdout.decode(errors="replace").splitlines():
        if line.startswith("@@RESULT@@"):
            result_line = line[len("@@RESULT@@"):]
    if result_line is None:
        raise RuntimeError("whois lookup returned no result")

    data = json.loads(result_line)
    if not data.get("ok"):
        raise RuntimeError(data.get("error", "unknown whois error"))
    return data["registered"], "whois-fallback"


async def check_via_rdap(session, rdap_base_url, domain, proxy, timeout, retries) -> tuple:
    url = rdap_base_url.rstrip("/") + f"/domain/{domain}"
    last_exc = None
    for attempt in range(retries + 1):
        try:
            async with session.get(
                url, proxy=proxy, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True,
            ) as resp:
                if resp.status == 200:
                    return True, "rdap"
                if resp.status == 404:
                    return False, "rdap"
                if resp.status in (429, 503):
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                await asyncio.sleep(0.5)
        except Exception as e:
            last_exc = e
            await asyncio.sleep(0.5 * (attempt + 1))
    raise RuntimeError(f"RDAP lookup failed after {retries + 1} attempts: {last_exc}")


async def check_domain(session, rdap_map, proxies_cycle, config, name, ext):
    domain = f"{name}{ext}"
    tld = ext.lstrip(".")
    proxy = next(proxies_cycle) if proxies_cycle else None
    timeout = config["request_timeout_seconds"]
    retries = config["retries"]

    rdap_base = rdap_map.get(tld)
    method_used = None
    registered = None

    if rdap_base:
        try:
            registered, method_used = await check_via_rdap(session, rdap_base, domain, proxy, timeout, retries)
        except Exception:
            registered = None

    if registered is None:
        try:
            registered, method_used = await check_via_whois(domain, timeout)
        except Exception as e:
            return name, domain, ext, None, f"error: {e}"

    if config["delay_between_requests"] > 0:
        await asyncio.sleep(config["delay_between_requests"])

    return name, domain, ext, registered, method_used


# --------------------------------------------------------------------------
# Live dashboard
# --------------------------------------------------------------------------

def build_dashboard(stats: dict, available_hits: list, total: int, elapsed: float) -> Group:
    size = console.size
    pct = (stats["done"] / total * 100) if total else 0

    # Keep the progress bar width sane on narrow terminals.
    bar_width = max(10, min(40, size.width - 55))
    filled = int(bar_width * stats["done"] / total) if total else 0
    bar = Text()
    bar.append("█" * filled, style=C_PRIMARY2)
    bar.append("░" * (bar_width - filled), style=C_MUTED)

    header = Table.grid(padding=(0, 2))
    header.add_column(justify="left")
    header.add_column(justify="left")
    header.add_column(justify="left")
    header.add_column(justify="left")
    header.add_row(
        Text(f"⏳ Loaded", style=f"bold {C_TEXT}"),
        Text(f"✔ Available", style=f"bold {C_GOOD}"),
        Text(f"✘ Taken", style=f"bold {C_BAD}"),
        Text(f"… Unchecked", style=f"bold {C_MUTED}"),
    )
    header.add_row(
        Text(str(total), style=C_TEXT),
        Text(str(stats["available"]), style=C_GOOD),
        Text(str(stats["taken"]), style=C_BAD),
        Text(str(total - stats["done"]), style=C_MUTED),
    )

    stats_line = Text()
    stats_line.append(f"{pct:5.1f}%  ", style=f"bold {C_PRIMARY2}")
    stats_line.append_text(bar)
    stats_line.append(f"   {stats['done']}/{total}", style=C_MUTED)
    stats_line.append(f"   {elapsed:.1f}s", style=C_MUTED)
    if stats["errors"]:
        stats_line.append(f"   {stats['errors']} errors", style=C_WARN)

    stats_panel = Panel(
        Group(header, Text(""), stats_line),
        title="[bold]LIVE STATS[/]",
        border_style=C_PRIMARY,
        box=box.ROUNDED,
    )

    # The live dashboard renders in a full-screen alternate buffer, so it must
    # never be taller than the actual terminal window or content gets clipped.
    # Reserve enough lines for the stats panel + the hits panel's own chrome,
    # then only show as many hit rows as will actually fit.
    STATS_PANEL_HEIGHT = 7
    HITS_PANEL_CHROME = 5
    max_hit_rows = max(3, size.height - STATS_PANEL_HEIGHT - HITS_PANEL_CHROME)

    # Only ever show AVAILABLE domains in the scrolling results list
    if available_hits:
        shown = available_hits[-max_hit_rows:]
        hits_table = Table(box=box.SIMPLE_HEAVY, expand=True, show_header=True, header_style=f"bold {C_GOOD}")
        hits_table.add_column("✔ AVAILABLE DOMAIN", style=f"bold {C_GOOD}")
        hits_table.add_column("via", style=C_MUTED, justify="right")
        for domain, method in shown:
            hits_table.add_row(domain, method)
        title = f"[bold {C_GOOD}]AVAILABLE DOMAINS FOUND ({len(available_hits)})[/]"
        if len(available_hits) > len(shown):
            title += f"  [dim]— showing last {len(shown)}[/]"
        hits_panel = Panel(hits_table, title=title, border_style=C_GOOD, box=box.ROUNDED)
    else:
        hits_panel = Panel(
            Align.center(Text("no available domains found yet...", style=f"italic {C_MUTED}")),
            title=f"[bold {C_GOOD}]AVAILABLE DOMAINS FOUND (0)[/]",
            border_style=C_GOOD, box=box.ROUNDED,
        )

    return Group(stats_panel, hits_panel)


async def run_checks(config: dict):
    names = load_names(config["namelist_file"])
    proxies = load_proxies(config.get("proxy_list_file", ""))
    proxies_cycle = itertools.cycle(proxies) if proxies else None
    extensions = config["extensions"]

    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    print_banner("preparing scan...")

    connector = aiohttp.TCPConnector(limit=config["max_concurrency"], ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"Accept": "application/rdap+json"}) as session:
        with console.status(f"[{C_PRIMARY2}]Fetching RDAP registry map...", spinner="dots"):
            rdap_map = await fetch_rdap_bootstrap(session)

        missing_tlds = sorted({e.lstrip(".") for e in extensions if e.lstrip(".") not in rdap_map})
        if missing_tlds:
            note = ", ".join(missing_tlds)
            if HAVE_WHOIS:
                console.print(f"[{C_WARN}]No RDAP server known for:[/] {note} -> using WHOIS fallback.")
            else:
                console.print(f"[{C_WARN}]No RDAP server known for:[/] {note}, and python-whois isn't installed.")

        semaphore = asyncio.Semaphore(config["max_concurrency"])

        tasks = []
        total = 0
        for raw_name in names:
            clean = normalize_name(raw_name)
            if not clean:
                console.print(f"[{C_WARN}]Skipping[/] '{raw_name}': could not derive a valid domain label.")
                continue
            for ext in extensions:
                total += 1

                async def bound_check(name=clean, ext=ext):
                    async with semaphore:
                        return await check_domain(session, rdap_map, proxies_cycle, config, name, ext)

                tasks.append(asyncio.create_task(bound_check()))

        results = []
        stats = {"done": 0, "available": 0, "taken": 0, "errors": 0}
        available_hits = []

        start = time.time()
        # Full-screen alternate buffer for the live dashboard: totally isolated
        # from anything printed before it, and cleanly restores the terminal
        # to its prior state the moment the scan finishes.
        with Live(build_dashboard(stats, available_hits, total, 0), console=console,
                  refresh_per_second=12, screen=True) as live:
            for coro in asyncio.as_completed(tasks):
                name, domain, ext, registered, method = await coro
                stats["done"] += 1
                if registered is None:
                    stats["errors"] += 1
                elif registered:
                    stats["taken"] += 1
                else:
                    stats["available"] += 1
                    available_hits.append((domain, method))

                results.append((name, domain, ext, registered, method))
                live.update(build_dashboard(stats, available_hits, total, time.time() - start))

        elapsed = time.time() - start

    # ---- write outputs ----
    registered_lines, unregistered_lines, error_lines = [], [], []
    per_name_registered = {}
    for name, domain, ext, registered, method in results:
        per_name_registered.setdefault(name, False)
        if registered is True:
            registered_lines.append(f"{name}\t{domain}\t{method}")
            per_name_registered[name] = True
        elif registered is False:
            unregistered_lines.append(f"{name}\t{domain}\t{method}")
        else:
            error_lines.append(f"{name}\t{domain}\t{method}")

    fully_available = sorted(n for n, has_reg in per_name_registered.items() if not has_reg)

    (output_dir / "registered_domains.txt").write_text(
        "\n".join(sorted(registered_lines)) + ("\n" if registered_lines else ""), encoding="utf-8")
    (output_dir / "unregistered_domains.txt").write_text(
        "\n".join(sorted(unregistered_lines)) + ("\n" if unregistered_lines else ""), encoding="utf-8")
    (output_dir / "errors.txt").write_text(
        "\n".join(sorted(error_lines)) + ("\n" if error_lines else ""), encoding="utf-8")
    (output_dir / "fully_available_names.txt").write_text(
        "\n".join(fully_available) + ("\n" if fully_available else ""), encoding="utf-8")
    (output_dir / "results.json").write_text(
        json.dumps([{"name": n, "domain": d, "extension": e, "registered": r, "method": m}
                    for n, d, e, r, m in results], indent=2), encoding="utf-8")

    print_banner("scan complete")
    section_rule("SUMMARY", style=C_GOOD)
    summary = Table.grid(padding=(0, 3))
    summary.add_column(justify="left")
    summary.add_column(justify="left")
    summary.add_row(Text("✔ Available", style=f"bold {C_GOOD}"), Text(str(len(unregistered_lines)), style=C_GOOD))
    summary.add_row(Text("✘ Taken", style=f"bold {C_BAD}"), Text(str(len(registered_lines)), style=C_BAD))
    summary.add_row(Text("⚠ Errors", style=f"bold {C_WARN}"), Text(str(len(error_lines)), style=C_WARN))
    summary.add_row(Text("⏱ Elapsed", style=f"bold {C_TEXT}"), Text(f"{elapsed:.1f}s", style=C_TEXT))
    console.print(Align.center(summary))
    console.print()
    console.print(Align.center(Panel(
        f"[bold]{output_dir}/[/]\n"
        f"  registered_domains.txt\n  unregistered_domains.txt\n  errors.txt\n"
        f"  fully_available_names.txt\n  results.json",
        title="[bold]OUTPUT FILES[/]", border_style=C_PRIMARY, box=box.DOUBLE, padding=(1, 3),
    )))
    console.print()
    footer_bar("press enter to return to the menu")
    console.input("")


def run_check_entrypoint(config: dict):
    try:
        asyncio.run(run_checks(config))
    except FileNotFoundError as e:
        console.print(f"\n[bold {C_BAD}]Error:[/] {e}")
        footer_bar("press enter to continue")
        console.input("")
    except KeyboardInterrupt:
        console.print(f"\n[{C_WARN}]Interrupted.[/]")


# --------------------------------------------------------------------------
# Console menu
# --------------------------------------------------------------------------

def print_config_summary(config: dict):
    print_banner("current configuration")
    t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    t.add_column(style=f"bold {C_PRIMARY2}")
    t.add_column(style=C_TEXT)
    t.add_row("Name list file", config["namelist_file"])
    t.add_row("Proxy list file", config.get("proxy_list_file") or "(none)")
    t.add_row("Extensions", ", ".join(config["extensions"]))
    t.add_row("Output directory", config["output_dir"])
    t.add_row("Max concurrency", str(config["max_concurrency"]))
    t.add_row("Request timeout", f"{config['request_timeout_seconds']}s")
    t.add_row("Delay per request", f"{config['delay_between_requests']}s")
    t.add_row("Retries", str(config["retries"]))
    panel = Panel(t, title="[bold]CONFIGURATION[/]", border_style=C_PRIMARY, box=box.DOUBLE, padding=(1, 3))
    console.print(Align.center(panel))
    console.print()
    footer_bar("press enter to return to the menu")
    console.input("")


MENU_ICONS = {
    "Run domain check": "🔍",
    "Edit configuration": "⚙",
    "View configuration": "👁",
    "Create configuration": "✨",
    "Exit": "🚪",
}


def styled_menu(options: list, title: str = "MAIN MENU") -> str:
    print_banner()
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=False)
    table.add_column(style=f"bold {C_PRIMARY2}", justify="right")
    table.add_column(style=C_TEXT)
    for key, label in options:
        icon = MENU_ICONS.get(label, "•")
        table.add_row(f"[{key}]", f"{icon}  {label}")
    panel = Panel(table, title=f"[bold {C_PRIMARY}] {title} [/]", border_style=C_PRIMARY,
                  box=box.DOUBLE, padding=(1, 4))
    console.print(Align.center(panel))
    console.print()
    footer_bar("type a number and press enter  •  ctrl+c to quit")
    console.print()
    valid = [k for k, _ in options]
    return Prompt.ask(f"[bold {C_PRIMARY}]›[/]", choices=valid, show_choices=False)


def main_menu():
    while True:
        config = load_config()
        if config is None:
            choice = styled_menu([("1", "Create configuration"), ("2", "Exit")], title="WELCOME")
            if choice == "1":
                config_wizard()
            else:
                return
            continue

        choice = styled_menu([
            ("1", "Run domain check"),
            ("2", "Edit configuration"),
            ("3", "View configuration"),
            ("4", "Exit"),
        ])

        if choice == "1":
            run_check_entrypoint(config)
        elif choice == "2":
            config_wizard(existing=config)
        elif choice == "3":
            print_config_summary(config)
        elif choice == "4":
            console.print(f"\n[{C_MUTED}]Goodbye![/]\n")
            return


# --------------------------------------------------------------------------
# Terminal sizing
# --------------------------------------------------------------------------

TARGET_COLS = 110
TARGET_LINES = 42


def try_resize_terminal(cols: int = TARGET_COLS, lines: int = TARGET_LINES):
    """
    Best-effort: ask the terminal to grow so the full banner and dashboard
    have room. Silently does nothing on terminals that don't support resizing
    (e.g. many CI environments, some Linux terminals) or when output isn't a
    real interactive terminal — the responsive layout in print_banner() and
    build_dashboard() handles those cases gracefully either way.
    """
    if not sys.stdout.isatty():
        return
    try:
        current = console.size
        if current.width >= cols and current.height >= lines:
            return  # already big enough
        if os.name == "nt":
            os.system(f"mode con: cols={cols} lines={lines}")
        else:
            sys.stdout.write(f"\x1b[8;{lines};{cols}t")
            sys.stdout.flush()
    except Exception:
        pass


def main():
    import argparse

    global CONFIG_PATH

    parser = argparse.ArgumentParser(description="Check name.<ext> domain registration status.")
    parser.add_argument("--run", action="store_true", help="Run immediately using the existing config.json")
    parser.add_argument("--configure", action="store_true", help="Run the config wizard and exit")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to a config.json file")
    args = parser.parse_args()

    CONFIG_PATH = Path(args.config)
    try_resize_terminal()

    if args.configure:
        config_wizard(existing=load_config())
        return

    if args.run:
        config = load_config()
        if config is None:
            console.print(f"[{C_BAD}]No config.json found.[/] Run with --configure first, "
                           f"or just run with no flags for the menu.")
            sys.exit(1)
        run_check_entrypoint(config)
        return

    main_menu()


if __name__ == "__main__":
    main()
