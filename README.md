<div align="center">

```
        ▄▄▄▄▄▄▄▄▄▄
      ▄██████████████▄
    ▄██▀▀▀▀▀▀▀▀▀▀▀▀▀▀██▄
   ██▀     ▄▄▄▄▄▄     ▀██
  ██     ▄█▀▀▀▀▀▀█▄     ██
  ██    ██   ●●   ██    ██
  ██    ██   ●●   ██    ██
  ██     ▀█▄▄▄▄▄▄█▀     ██
   ██▄     ▀▀▀▀▀▀     ▄██
    ▀██▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▀
      ▀██▄▄▄▄▄▄▄▄▄▄██▀
        ▀▀██▄▄▄▄██▀▀
             ▀▀▀▀
              ▀█▄
               ▀█▄
                ▀█▄
```

# Domain Hunter

**A fast, async, config-driven console app that hunts down available domain names — across as many extensions as you want.**

[![Python](https://img.shields.io/badge/python-3.9%2B-orange.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-ffb74d.svg)](#license)
[![Made with rich](https://img.shields.io/badge/UI-rich%20%2B%20pyfiglet-ff9800.svg)](https://github.com/Textualize/rich)

</div>

---

## What it does

Give it a list of names (`Acme`, `blue sky`, `John Smith`, whatever) and a list of extensions (`.com`, `.net`, `.io`, ...), and it will:

1. Normalize every name into a valid domain label
2. Check each `name + extension` combination, concurrently, using **RDAP** (fast, structured, near-universal) with an automatic **WHOIS fallback** for extensions RDAP doesn't cover
3. Show you a **live dashboard** while it works — but only ever lists the domains that came back *available*, so the noise of "taken" results never clutters your screen
4. Write everything out to clean, ready-to-use result files

No coding required after the first setup — it's a menu-driven console app with its own configuration wizard.

---

## Preview

<table>
<tr>
<td valign="top" width="50%">

**Live dashboard**

```
╭──────────── LIVE STATS ────────────╮
│ ⏳ Loaded  ✔ Available  ✘ Taken   │
│ 100        10            20        │
│                    … Unchecked: 70 │
│                                    │
│ 30.0% █████████░░░░░░░░  30/100    │
╰────────────────────────────────────╯
╭── AVAILABLE DOMAINS FOUND (10) ───╮
│ ✔ AVAILABLE DOMAIN         via    │
│ ────────────────────────────────  │
│ blue-sky.com               rdap   │
│ coolname.net               rdap   │
│ acmecorp.io          whois-fall…  │
╰────────────────────────────────────╯
```

</td>
<td valign="top" width="50%">

**Main menu**

```
╔═════════════  MAIN MENU  ═════════════╗
║                                        ║
║   [1]   🔍  Run domain check          ║
║   [2]   ⚙   Edit configuration        ║
║   [3]   👁   View configuration        ║
║   [4]   🚪  Exit                      ║
║                                        ║
╚════════════════════════════════════════╝

  type a number and press enter  •  ctrl+c to quit
```

</td>
</tr>
</table>

The real thing renders in full color (warm orange/amber theme) with a gradient ASCII badge logo up top. On smaller terminal windows it automatically switches to a compact header and trims the live results list so nothing ever gets cut off — see [Display & terminal size](#display--terminal-size).

---

## Requirements

- Python 3.9+
- Packages: `aiohttp`, `python-whois`, `rich`, `pyfiglet`

```bash
pip install -r requirements.txt
```

---

## Quick start

```bash
python check_domains.py
```

That's it. On first run you'll land in a menu that walks you through building `config.json`. After that, running the script with no arguments always opens the menu; use `--run` to skip straight to a scan.

```bash
python check_domains.py            # interactive menu (default)
python check_domains.py --run      # run a scan immediately using config.json
python check_domains.py --configure          # (re)build config.json and exit
python check_domains.py --config other.json  # use a different config file
```

---

## Configuration

Everything lives in `config.json`, built for you by the in-app wizard (menu → **Edit configuration**). You can also hand-edit it directly:

```json
{
  "namelist_file": "names.txt",
  "proxy_list_file": "proxies.txt",
  "extensions": [".com", ".net", ".io"],
  "output_dir": "results",
  "max_concurrency": 30,
  "request_timeout_seconds": 8,
  "delay_between_requests": 0.0,
  "retries": 2
}
```

| Key | What it controls |
|---|---|
| `namelist_file` | Path to a text file, one name per line |
| `proxy_list_file` | Path to a text file of HTTP/HTTPS proxies, one per line (blank = no proxies) |
| `extensions` | List of TLDs to check each name against |
| `output_dir` | Where result files are written |
| `max_concurrency` | Max lookups in flight at once (higher = faster, more rate-limit risk) |
| `request_timeout_seconds` | Per-request timeout |
| `delay_between_requests` | Optional pause between requests, per worker slot |
| `retries` | Retries on rate-limiting (429) or transient errors |

### Name list format

One name per line — names are normalized automatically (lowercased, spaces stripped, punctuation removed):

```
Acme Corp
blue sky
John Smith
```

→ checked as `acmecorp`, `bluesky`, `johnsmith` against every configured extension.

### Proxy list format

One proxy per line, HTTP/HTTPS only:

```
http://123.45.67.89:8080
http://user:pass@123.45.67.89:8080
```

Proxies are rotated round-robin across requests. (SOCKS proxies aren't supported.)

---

## How the checking actually works

Most domain checkers either scrape WHOIS text (slow, one connection at a time, format varies by registry) or hit a single API. This one is built around **RDAP** — the structured JSON/HTTP protocol that has replaced WHOIS for the vast majority of registries:

1. On startup, it fetches IANA's official RDAP registry map (which TLD maps to which RDAP server), caching it locally for 30 days.
2. Every `name.extension` check is an async HTTP request — dozens can run concurrently, bounded by `max_concurrency`.
3. If a TLD has no RDAP server, it automatically falls back to WHOIS — run in an **isolated subprocess** so any noisy low-level socket errors from the WHOIS library (e.g. DNS resolution failures) are contained and never leak onto your screen.

This combination is both **fast** (concurrent RDAP beats serial WHOIS by a wide margin) and **quiet** (no more raw `Error trying to connect to socket...` spam).

---

## Output files

After a run, everything lands in your configured `output_dir`:

| File | Contents |
|---|---|
| `unregistered_domains.txt` | Available domains — `name`, `domain`, method (tab-separated) |
| `registered_domains.txt` | Taken domains |
| `fully_available_names.txt` | Names where **none** of the checked extensions were found registered |
| `errors.txt` | Lookups that failed (timeouts, rate limits, etc.) |
| `results.json` | Full structured report of every check |

---

## Display & terminal size

The whole UI is responsive:

- On a spacious terminal (**92+ columns, 34+ rows**) you get the full gradient ASCII logo, figlet wordmark, and roomy panels.
- On a smaller window, it automatically switches to a compact single-line header so the menu and content are never pushed off-screen.
- The live dashboard runs in its own full-screen buffer and dynamically limits how many "available" results it lists based on your current terminal height — it will never render more than actually fits, and cleanly restores your normal screen the moment a scan finishes.
- On startup, the app also makes a best-effort attempt to widen your terminal window to a comfortable size (via `mode con` on Windows, or a resize escape sequence elsewhere). This is silently skipped on terminals that don't support it — the responsive layout above handles those cases regardless.

For the best experience, a window of at least **100×35** is recommended, but nothing requires it.

---

## Performance tips

- `max_concurrency` is your main speed lever. 20–50 is a reasonable range; going much higher increases the odds of getting rate-limited (429s) by registries.
- RDAP is the fast path — WHOIS fallback (used only for TLDs without RDAP support) is inherently slower since it spawns a subprocess per lookup. If you're checking an extension heavily, check whether it appears in the IANA RDAP bootstrap; if not, expect that portion of the run to take longer.
- Proxies help avoid rate-limiting when scanning large lists, but add network overhead — only enable them if you're seeing lots of 429s in `errors.txt`.

---

## Troubleshooting

**"No RDAP server known for: ..."**
That TLD isn't in the IANA RDAP bootstrap yet. The app will use WHOIS instead automatically — this is just informational.

**Lots of entries in `errors.txt`**
Usually a network/firewall restriction, an unreachable WHOIS server, or aggressive rate-limiting. Try lowering `max_concurrency`, adding a `delay_between_requests`, or adding proxies.

**Colors/emoji look off**
Make sure your terminal supports ANSI truecolor and UTF-8 (most modern terminals do — Windows Terminal, iTerm2, GNOME Terminal, etc. all work well; very old terminals may render icons as boxes).

---

## License

MIT — do whatever you'd like with it.
