# IROpenRelayFinder

A Linux-first, stdlib-only, high-control proxy and scanner toolkit for dynamic IP routing, domain-specific race selection, and DPI desync workflows.

This project is designed for maintainability and offline operation:
- Python runtime dependencies: **standard library only**
- External Python packages: **none required**
- Optional system tools: `nmap`, `masscan` (if present, scanner can leverage them)

---

## 1) What This Project Does

IROpenRelayFinder combines multiple operational capabilities in one CLI/TUI:

1. **Adaptive routing proxy**
   - Maintains exact and wildcard domain routes.
   - Races multiple candidate IPs when no valid route exists.
   - Caches winners and isolates failing paths per-domain.

2. **IP discovery and verification scanner**
   - Expands input targets (IPs/CIDRs/ASNs).
   - Verifies network/service viability through scanning/probing.
   - Stores results in timestamped scan files.

3. **DPI desync operation modes**
   - Supports strategy selection and rotation.
   - Supports manual or mined SNI/IP target selection.
   - Supports mixed mode (white-IP + DPI desync behavior).

4. **Operational utilities**
   - Domain reroute and per-domain IP banning.
   - ASN inspection and regional/provider intelligence.
   - Instant pool loading for immediate proxy operation.

---

## 2) Quick Start

### Prerequisites

- Python 3.9+ recommended
- Linux recommended (primary target)
- Root privileges required for some DPI/raw-socket paths

### Launch UI (default)

```bash
python main.py
```

or explicitly:

```bash
python main.py --core ui
```

### Run Smoke Harness

```bash
python main.py --core smoke
```

or directly:

```bash
python scripts/smoke_harness.py
```

### Other cores

```bash
python main.py --core desync_scanner
python main.py --core sni_scanner
python main.py --core autotuner
```

---

## 3) Usage Guide

### UI Main Menu (Operational Flow)

The typical lifecycle is:

1. **Scan targets** (`menu_scan`)
2. **Load/manage pool** (`menu_manage_pool`)
3. **Run proxy mode** (white-IP, DPI, or mixed)
4. **Inspect and reroute** as failures are observed

### Modes

- **white_ip**: pure dynamic white-IP routing
- **dpi_desync**: DPI-evasion-focused routing path
- **mixed**: combines white-IP behavior with DPI desync configuration

### Instant Connect

Use this when you already have candidate IPs and want immediate operation:
- Load from file or paste manually
- Deduplicates and shuffles inputs
- Truncates to a stability cap for racing behavior

### Reroute Domain (Failure Recovery)

When a route degrades for a specific domain:
- Remove exact/wildcard route entries for that domain
- Ban the failed IP **only for that base domain**
- Keep the same IP usable for unrelated domains
- Trigger fresh race on next request

---

## 4) Features

### Core Features

- Dynamic domain-aware routing with exact + wildcard cache
- Concurrent race selection for HTTPS targets
- Per-domain ban isolation model
- Timestamped scan results and cyclic archives
- DPI strategy management with toggles and strategy sets
- ASN intelligence integration from local datasets

### Reliability Features

- Centralized path resolution (CWD-independent)
- Atomic file writes for critical state files
- Migration-aware data read/write for legacy compatibility
- Runtime state façade to reduce global-state coupling
- Service abstractions for route/scan/app workflows

### Refactor Highlights

- Monolithic UI split into focused modules
- Explicit service boundaries:
  - `RouteService`
  - `ScanService`
  - `AppService`
- Safer storage primitives and deterministic file handling

---

## 5) Project Structure

```text
iropen-relay-finder/
├── main.py
├── README.md
├── scripts/
│   └── smoke_harness.py
├── cores/
│   ├── ui.py
│   ├── ui_layout.py
│   ├── ui_asn.py
│   ├── ui_scan.py
│   ├── ui_tools.py
│   ├── ui_dpi.py
│   ├── white_core.py
│   ├── scanner.py
│   ├── desync_scanner.py
│   ├── sni_scanner.py
│   ├── autotuner.py
│   └── smoke.py
├── utils/
│   ├── config.py
│   ├── paths.py
│   ├── storage.py
│   ├── data_store.py
│   ├── runtime_state.py
│   ├── route_manager.py
│   ├── route_service.py
│   ├── scan_service.py
│   ├── app_service.py
│   ├── helpers.py
│   ├── asn_engine.py
│   └── workers.py
├── assets/
├── IranASNs/
└── cyclic_archives/
```

---

## 6) Architecture (Whitepaper-Level)

### 6.1 Design Goals

1. **No Python package dependencies** (offline-friendly)
2. **Operational resilience** under partial failures
3. **Composable modules** with clear ownership
4. **Progressive migration** without hard breakage
5. **High-throughput concurrency** using `asyncio`

### 6.2 Layered Model

#### Layer A — Entry and orchestration
- `main.py`: bootstrap + core launcher + platform tuning
- `cores/ui.py`: operator control loop

#### Layer B — Domain services
- `utils/route_service.py`: route operations boundary
- `utils/scan_service.py`: scan operations boundary
- `utils/app_service.py`: UI-triggered mutable state operations

#### Layer C — Domain engines
- `utils/route_manager.py`: route cache + race logic
- `cores/scanner.py`: probing/scanning execution
- `utils/workers.py`: background verification and maintenance

#### Layer D — State and persistence
- `utils/runtime_state.py`: access façade for hot runtime state
- `utils/config.py`: persistent settings + global operational constants
- `utils/storage.py`: atomic and safe file IO
- `utils/data_store.py`: migration-aware file access
- `utils/paths.py`: deterministic project paths

### 6.3 Module Coupling Strategy

The refactor intentionally moves from direct module mutation toward explicit APIs:

- Before: UI modules mutating `config.*` and route maps directly
- After: UI modules call `AppService` / `RouteService` / `ScanService` methods

This reduces implicit side effects and improves testability and maintainability.

---

## 7) Core Technical Methods

## 7.1 Deterministic Pathing

`utils/paths.py` ensures all important files resolve from project root, not current shell directory.

Implications:
- No accidental file duplication due to changed CWD
- Predictable location of scan/cache/config artifacts
- Safer automation and cron/systemd compatibility

## 7.2 Atomic Persistence

`utils/storage.py` provides safe write patterns for critical files.

Typical pattern:
1. Write content to a temp file in same filesystem
2. Flush/sync as needed
3. Atomic replace target file

This minimizes corruption risk during interruption or process crash.

## 7.3 Migration-Aware Data Access

`utils/data_store.py` supports reading legacy locations and writing through the modern storage model.

Benefits:
- Gradual upgrades without immediate one-shot migration
- Backward readability for existing deployments

## 7.4 Routing and Race Resolution

`utils/route_manager.py` implements a cache-then-race strategy:

1. Normalize target host/domain context
2. Skip race for direct/native cases (e.g., local or special domains)
3. Attempt exact/wildcard cache hit
4. Validate against per-domain ban list
5. If unresolved, run concurrent verification race over candidate IP pool
6. Promote winner into route cache and persist

This approach balances speed (cache hits) with resilience (fresh race on failures).

## 7.5 Strict Verification

Verification includes TLS and response-level sanity checks to avoid accepting generic or poisoned endpoints.

Conceptually:
- Establish secure connection with proper server name context
- Validate certificate suitability for domain
- Optionally perform HTTP probe for sensitive domains
- Classify responses to distinguish acceptable vs degraded paths

## 7.6 Per-Domain Ban Isolation

Failed IPs are not globally blackholed by default.

Instead, bans are attached to base domains. This enables:
- Fast isolation of failing routes for one service
- Continued reuse of same IP for other services where valid

## 7.7 DPI Desync Strategy System

DPI mode supports multiple packet behavior strategies and toggles:
- Strategy set selection
- Active strategy tracking
- Fragmentation toggle
- Verbose logging toggle

The UI flow updates configuration through `AppService`, then persists durable settings through `config.save_config()`.

## 7.8 Scanner Pipeline

The scanner subsystem typically follows:

1. Target expansion (raw IP/CIDR/ASN to concrete IP list)
2. Preflight scanning/probing (optionally with external tool acceleration)
3. Service/domain verification
4. Result ranking and persistence
5. Dynamic pool population from top verified entries
6. Permanent cache enrichment

## 7.9 Runtime State Facade

`utils/runtime_state.py` centralizes mutable runtime maps/counters access.

This reduces direct, ad-hoc mutations across modules and allows future replacement with stricter state containers if needed.

---

## 8) Data and File Semantics

### Key Files

- `white_routes.txt`: persisted exact/wildcard route mappings
- `banned_routes.txt`: per-domain isolated banned IP entries
- `failed_routes.txt`: failed-domain log trail
- `white_ips_cache.txt`: long-lived verified IP cache
- `scanner_config.json`: durable runtime configuration
- `desync_pairs.json`: mined SNI-to-IP associations
- `scan_YYYYMMDD_HHMMSS.json`: scan result snapshots
- `cyclic_archives/round_*.json`: cyclic scan round archives

### Route File Model

- Exact routes map domain → IP
- Wildcard routes map base-domain namespace → IP
- In-memory split maps are rewritten as normalized route lines for persistence

---

## 9) Concurrency and Performance

- Uses `asyncio` for high concurrency operations
- Uses lock/semaphore primitives to control race and write contention
- Keeps race locks keyed by domain to avoid duplicate simultaneous races
- Supports Linux resource-limit tuning at startup (when available)

### Platform Notes

- Linux/macOS path: default asyncio loop policy
- Windows path: proactor policy and known-error suppression for stability
- Optional `uvloop` usage if installed (not required)

---

## 10) Security and Operational Considerations

1. **Privilege boundaries**
   - Some DPI paths require elevated privileges.
2. **Input trust model**
   - Treat imported IP/domain feeds as untrusted; verify before promotion.
3. **File integrity**
   - Atomic writes reduce partial-write corruption risk.
4. **Route poisoning resistance**
   - Strict verification and classification help prevent bad endpoint promotion.

---

## 11) Smoke Harness and Maintenance

### Smoke Harness Scope

`scripts/smoke_harness.py` validates non-network critical behavior:
- scan file ordering logic
- app service mutation semantics
- route-cache clearing flow
- reroute/ban persistence path
- scan service delegation contract

### Run

```bash
python main.py --core smoke
```

or:

```bash
python scripts/smoke_harness.py
```

### Recommended Routine

- Run smoke harness after refactors
- Run targeted compile checks on changed modules
- Keep route and ban files under operational observation for drift patterns

---

## 12) Configuration Reference

Important runtime config fields (in `scanner_config.json`):

- `CONNECTION_MODE`
- `PROXY_PORT`
- `DPI_SNI`
- `DPI_IP`
- `DPI_STRATEGIES`
- `DPI_FRAGMENTATION`
- `MAX_CONCURRENT_SCANS`
- tuned scan-rate parameters

Operational guidance:
- Keep a conservative initial strategy set.
- Introduce additional DPI strategies incrementally.
- Prefer stable, repeatedly verified IPs for baseline operation.

---

## 13) Troubleshooting

### No routes / no pool loaded
- Ensure at least one `scan_*.json` exists.
- Run scan flow and then load/manage pool.

### Domain repeatedly fails after cache hit
- Use reroute tool to isolate bad domain/IP mapping.
- Confirm ban entry is persisted in `banned_routes.txt`.

### DPI mode unstable
- Reduce strategy count to one known-good strategy.
- Disable optional toggles temporarily and retest.

### Permission errors in DPI workflows
- Re-run with elevated privileges when required by raw packet path.

---

## 14) Development Principles

- Keep modules focused and single-purpose.
- Prefer service methods over direct global state mutation.
- Preserve stdlib-only Python dependency model.
- Favor deterministic paths and atomic persistence for reliability.

---

## 15) License / Usage

If you distribute or deploy this project, define your operational and legal policy according to local laws and the environments where it is used.

