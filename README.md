# IROpenRelayFinder

IROpenRelayFinder is a low-level networking research toolkit for **authorized relay/path testing** in controlled environments.

This project is intended for:
- security research in lab or approved production scopes
- defensive validation (network resilience, routing behavior, protocol testing)
- educational use (TCP/IP behavior, scanning methodology, packet-level diagnostics)

Current implementation focuses on Iranian IP space datasets and workflows.

---

## Important Use Policy (Read First)

### ✅ Allowed use

Use this repository only when **all** of the following are true:
- You own the target environment, or you have explicit written permission.
- Your testing scope is clearly defined and lawful.
- Your purpose is defensive, academic, or educational.
- You comply with local laws, provider terms, and organizational policy.

### ❌ Prohibited use

Do **not** use this project for abuse or malicious activity, including:
- DDoS, amplification, traffic flooding, or service disruption
- stealth/unauthorized scanning outside approved scope
- bypassing controls to harm systems or users
- deceiving systems, operators, or logs (log tampering/evasion)
- any offensive operation without explicit legal authorization

Repositories that primarily enable abuse may violate GitHub policies and can be restricted or removed.

### Responsible disclosure

If you discover a real vulnerability during authorized testing:
- stop non-essential probing
- document findings responsibly
- report through the asset owner’s approved disclosure channel

---

## Scope and Design

- Academic/research-focused operation
- Linux-first, Python stdlib-oriented workflow
- Configuration-driven scanner behavior
- Persistent, timestamped outputs for reproducible analysis

---

## Core Capabilities

1. Route-aware relay/path testing
   - Maintains exact and wildcard domain routes
   - Reuses successful paths when available
   - Tracks failures per domain

2. Candidate discovery workflow
   - Accepts IP, CIDR, and ASN input
   - Expands and validates candidate targets
   - Stores results in timestamped snapshots

3. Diagnostics and tuning
   - Multiple operating modes
   - Adaptive/runtime configuration support
   - Reusable state between runs

4. Operational utilities
   - Domain reroute support
   - ASN/regional dataset inspection
   - Pool loading for runtime use

---

## Quick Start

### Requirements

- Python 3.9+
- Linux recommended
- Elevated privileges may be required for some low-level paths

### Launch UI

```bash
python main.py
```

### Run smoke core

```bash
python main.py --core smoke
```

Alternative harness:

```bash
python scripts/smoke_harness.py
```

---

## How to Use (Modes and Buttons)

This UI has two operator modes. Use only on authorized targets.

### 1) IROpenRelayFinder Mode (White Routing UI)

Use this mode for building and operating a verified relay pool.

- `[1] Scan Targets and Build IP Pool`: runs target discovery/verification and saves ranked results.
- `[2] Reload IP Pool from Latest Scan`: loads fastest recent verified endpoints into dynamic runtime pool.
- `[3] Instant Connect (Load IPs without scan)`: validates provided endpoints quickly and loads usable ones.
- `[4] Change Proxy Port`: updates local proxy listen port.
- `[5] Clear Routing Cache`: clears current route cache.
- `[6] Force Reroute Domain and Ban IP`: removes current bad route for one domain and bans that IP for that domain.
- `[7] Inspect IPs (ASN and Type)`: shows ASN/type metadata for pool or custom inputs.
- `[8] Auto-Tune Scan Rates`: runs scan-rate tuner for better local stability/performance.
- `[9] Manage Routing Rules`: manage `DO_NOT_ROUTE` and `ALWAYS_ROUTE` patterns.
- `[s] SOCKS5 Proxy Scanner`: scans candidate SOCKS5 proxies.
- `[h] HTTP-Only Proxy Scanner`: scans candidate HTTP proxies.
- `[c] Install MMDF CA`: installs/refreshes local root CA for MMDF TLS interception workflows.
- `[w] Start Proxy (White Routing)`: starts proxy using verified white routing.
- `[x] Switch to Desync Mode`: opens Desync UI mode.
- `[0] Exit`: closes the application.

### 2) Desync Mode (DPI UI)

Use this mode for authorized DPI-resilience research and controlled testing.

- `[1] Configure DPI Desync Strategies`: choose/toggle packet desync strategies, fragmentation, and DPI log visibility.
- `[2] Select DPI Target (SNI/IP)`: set fake SNI and clean IP manually or from mined pairs.
- `[3] Scan/Mine DPI SNI Pairs`: mine candidate SNI↔IP pairs for desync workflows.
- `[4] SNI Scanner (Carrier Discovery)`: runs SNI scanner module (when available).
- `[5] Change Proxy Port`: updates local proxy listen port.
- `[6] Clear Routing Cache`: clears current route cache.
- `[s] SOCKS5 Proxy Scanner`: scans candidate SOCKS5 proxies.
- `[h] HTTP-Only Proxy Scanner`: scans candidate HTTP proxies.
- `[c] Install MMDF CA`: certificate setup helper for MMDF-related flows.
- `[d] Start Proxy (DPI Desync)`: starts proxy in DPI desync connection mode.
- `[m] Start Proxy (Mixed)`: starts proxy in mixed mode (white routing + DPI desync behavior).
- `[x] Switch to IROpenRelayFinder Mode`: returns to White Routing UI mode.
- `[0] Exit`: closes the application.

### 3) Important submenus you will use often

#### Scan Source (`[1]` in White Routing mode)
- `[1]` Load targets from file
- `[2]` Paste targets manually
- `[3]` Use permanent white cache
- `[4]` Mine Cloudflare CNAME IPs
- `[5]` Select targets from IranASN database

#### Scan Method (inside scan flow)
- `[1]` Normal asyncio scan
- `[2]/[3]` Masscan/Nmap options (shown only if installed)
- `[d]` Toggle debug mode
- `[s]` Start scan with current settings

#### Instant Connect (`[3]` in White Routing mode)
- `[1]` Load IPs from file
- `[2]` Paste IPs manually

#### MMDF CA menu (`[c]`)
- `[1]` Install/refresh CA in OS trust store
- `[2]` Show CA file paths for manual install
- `[3]` Re-generate CA files

#### Routing Rules (`[9]`)
- `[1]` Add Do-Not-Route pattern
- `[2]` Add Always-Route pattern
- `[3]` Remove Do-Not-Route pattern
- `[4]` Remove Always-Route pattern

### 4) Recommended safe operating sequence

1. Confirm written authorization and scope.
2. In White Routing mode, run `[1]` or `[3]` to prepare usable endpoints.
3. Use `[2]` to load pool and verify status in header.
4. Start with `[w]` (or `[d]`/`[m]` only for authorized DPI research).
5. If instability appears, clear cache with `[5]`/`[6]`, tune settings, and retry with minimal scope.

---

## Typical Workflow

1. Start a scoped, authorized test run.
2. Review generated candidate results.
3. Load verified entries into the runtime pool.
4. Monitor failures and reroute domains where needed.

---

## Operating Modes

- `white_ip`: route through verified relay paths
- `mixed`: combines multiple routing behaviors

---

## Data and Output Files

- `white_routes.txt`: exact and wildcard route mappings
- `banned_routes.txt`: domain-scoped blocked entries
- `failed_routes.txt`: failure history
- `white_ips_cache.txt`: reusable verified pool
- `scanner_config.json`: runtime configuration
- `scan_YYYYMMDD_HHMMSS.json`: scan snapshots
- `cyclic_archives/round_*.json`: archived round outputs

---

## Operational Notes

- Treat all inputs as untrusted until validated.
- Keep scopes explicit and auditable.
- Preserve logs for reproducibility and review.
- Prefer minimal, controlled test profiles before scaling.

---

## Troubleshooting

### No results available
- Run a scanner/test core first.
- Confirm snapshot output files were generated.

### Domain repeatedly fails
- Reroute the domain.
- Review `banned_routes.txt` and `failed_routes.txt`.

### Unstable behavior
- Reduce config complexity.
- Retest with a minimal known-good profile.

---

## Legal and Ethical Reminder

By using this project, you agree to use it **only** for lawful, authorized, and defensive/educational purposes.

The maintainers do not endorse misuse and are not responsible for unauthorized or illegal operation by third parties.
