# IROpenRelayFinder

IROpenRelayFinder is an academic and educational toolkit for controlled relay testing and path verification.

It is limited to the Iranian IP space.

## Scope

- Academic and educational use only
- Tests only Iranian IP space
- Linux-first and stdlib-only
- No external Python dependencies required

## Overview

The toolkit provides a focused set of capabilities:

1. Route-aware relay testing
   - Maintains exact and wildcard domain routes
   - Reuses successful paths when available
   - Separates failures per domain

2. Tester workflow
   - Accepts IP, CIDR, and ASN input
   - Expands and validates candidate targets
   - Records results in timestamped files

3. Diagnostics and tuning
   - Supports several operating modes
   - Provides configuration-driven behavior
   - Stores reusable state for repeatable runs

4. Utility functions
   - Domain reroute support
   - ASN and regional dataset inspection
   - Pool loading for immediate testing

## Quick start

### Requirements

- Python 3.9 or newer recommended
- Linux recommended
- Elevated privileges may be needed for some low-level paths

### Start the UI

```bash
python main.py
```

### Run the smoke harness

```bash
python main.py --core smoke
```

or:

```bash
python scripts/smoke_harness.py
```

## Typical workflow

1. Run the tester
2. Review the resulting candidate pool
3. Load the verified entries into the runtime pool
4. Monitor failures and reroute when needed

## Supported modes

- white_ip: route through verified relay paths
- mixed: combines both behaviors

## Data files

- white_routes.txt: stored exact and wildcard routes
- banned_routes.txt: domain-scoped blocked entries
- failed_routes.txt: failure history
- white_ips_cache.txt: reusable verified pool
- scanner_config.json: runtime configuration
- scan_YYYYMMDD_HHMMSS.json: tester snapshots
- cyclic_archives/round_*.json: archived test rounds

## Notes on operation

- The tester is limited to Iranian IP space
- Inputs should be treated as untrusted until verified
- Results are persisted for repeatable academic analysis
- Atomic file handling is used where possible

## Troubleshooting

### No results available

- Run the tester first
- Confirm that the generated snapshot files exist

### A domain keeps failing

- Reroute the domain
- Check the saved ban and route entries

### Mode behavior seems unstable

- Reduce configuration complexity
- Retest with a minimal known-good setup

## Usage policy

This project is provided for academic and educational purposes only.
Use must remain within the Iranian IP space and in accordance with applicable law and local policy.
