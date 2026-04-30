#!/usr/bin/env python3
"""
Publishing script for IROpenRelayFinder releases.
- Runs smoke tests
- Bumps app version based on git history
- Creates a release zip file
- Creates a new commit
"""

import os
import sys
import re
import json
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path


def run_command(cmd, cwd=None, check=True):
    """Run a command and return (returncode, stdout, stderr).

    Accepts either a list of args or a string (which is parsed with shlex
    to avoid shell-splitting issues on paths that contain spaces, e.g.
    Windows ``sys.executable``).
    """
    import shlex
    if isinstance(cmd, str):
        argv = shlex.split(cmd, posix=(os.name != "nt"))
    else:
        argv = list(cmd)
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            shell=False,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        print(f"[-] Command failed: {e}")
        return 1, "", str(e)


def run_smoke_test(root_dir):
    """Run smoke tests."""
    print("\n[*] Running smoke tests...")
    smoke_harness_path = os.path.join(root_dir, "scripts", "smoke_harness.py")
    
    if not os.path.exists(smoke_harness_path):
        print(f"[-] Smoke harness not found: {smoke_harness_path}")
        return False
    
    returncode, stdout, stderr = run_command(
        [sys.executable, smoke_harness_path],
        cwd=root_dir
    )
    
    if stdout:
        print(stdout)
    if stderr:
        print(stderr, file=sys.stderr)
    
    if returncode == 0:
        print("[+] Smoke tests passed!")
        return True
    else:
        print("[-] Smoke tests failed!")
        return False


def get_version_from_config(root_dir):
    """Get current version from utils/config.py."""
    config_path = os.path.join(root_dir, "utils", "config.py")
    with open(config_path, "r") as f:
        content = f.read()
    
    match = re.search(r'VERSION = "([^"]+)"', content)
    if match:
        return match.group(1)
    return None


def parse_version(version_str):
    """Parse semantic version string into tuple."""
    parts = version_str.split(".")
    return tuple(int(p) for p in parts)


def get_commits_since_last_bump(root_dir):
    """Return commit subject lines since the last 'bump version' commit (exclusive)."""
    returncode, stdout, _ = run_command(
        ["git", "log", "--pretty=format:%s"],
        cwd=root_dir, check=False
    )
    if returncode != 0:
        return []
    messages = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.search(r'\bbump version\b', line, re.IGNORECASE):
            break
        messages.append(line)
    return messages


def compute_bump_type(messages):
    """
    Decide major / minor / patch from commit messages and volume.

    Priority:
      major – any commit contains "BREAKING CHANGE" or uses conventional "type!:" syntax
      minor – any commit starts with "feat:" / "feature:", OR ≥ 10 commits total
      patch – everything else
    """
    for msg in messages:
        low = msg.lower()
        if "breaking change" in low:
            return "major"
        if re.match(r'^[a-z]+(\([^)]+\))?!:', msg):
            return "major"

    for msg in messages:
        if re.match(r'^feat(ure)?(\([^)]+\))?:', msg, re.IGNORECASE):
            return "minor"

    if len(messages) >= 10:
        return "minor"

    return "patch"


def bump_version(version_str, bump_type="patch"):
    """Bump version according to bump_type: 'major', 'minor', or 'patch'."""
    major, minor, patch = parse_version(version_str)
    if bump_type == "major":
        return f"{major + 1}.0.0"
    if bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def get_recent_commits(root_dir, count=10):
    """Get recent commit messages (one-line format) for display."""
    returncode, stdout, _ = run_command(
        ["git", "log", "--oneline", "-n", str(count)],
        cwd=root_dir, check=False
    )
    return stdout.strip() if returncode == 0 else ""


def update_version_in_config(root_dir, new_version):
    """Update VERSION in utils/config.py."""
    config_path = os.path.join(root_dir, "utils", "config.py")
    
    with open(config_path, "r") as f:
        content = f.read()
    
    content = re.sub(
        r'VERSION = "[^"]+"',
        f'VERSION = "{new_version}"',
        content
    )
    
    with open(config_path, "w") as f:
        f.write(content)
    
    print(f"[+] Updated VERSION to {new_version}")


def get_exclude_patterns():
    """Get patterns for files/directories to exclude from release."""
    return {
        # Version control
        ".git",
        ".gitignore",

        # AI tool configs
        ".claude",
        ".codex",
        ".continue",

        # Virtual environments
        ".venv",
        "venv",
        "env",

        # Caches and build artifacts
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",

        # Editors / IDEs
        ".vscode",
        ".idea",

        # Local settings / runtime state
        "settings.local.json",
        "paused.conf",

        # Runtime-generated data (cache/output files)
        "white_routes.txt",
        "failed_routes.txt",
        "banned_routes.txt",
        "white_ips_cache.txt",
        "cloudflare_workers_ips.txt",
        "nmap_targets.txt",
        "clean_snis.txt",
        "desync_pairs.json",
        "socks5_cache.txt",
        "socks5_proxies.txt",
        "scan_*.json",
        "scan_cyclic_continuous.json",
        "masscan_targets_*",
        "masscan_results*",
        "nmap_results_*",
        "nmap_targets_*",

        # Temp and archive directories
        "tmp",
        "cyclic_archives",

        # Release artifacts (zips and releases dir)
        "releases",
    }


def should_exclude(file_path, root_dir, exclude_patterns):
    """Check if a file should be excluded from the release."""
    rel_path = os.path.relpath(file_path, root_dir)
    
    # Always exclude scanner_config.json from exclusion (special case)
    if rel_path == "data/scanner_config.json" or os.path.basename(file_path) == "scanner_config.json":
        return False
    
    # Check exclusion patterns
    for pattern in exclude_patterns:
        if pattern.startswith("scan_"):
            # Handle wildcard patterns
            if os.path.basename(file_path).startswith("scan_") and file_path.endswith(".json"):
                return True
        elif os.path.basename(file_path) == pattern or os.path.basename(file_path).endswith(pattern):
            return True
        elif pattern in rel_path:
            return True
    
    # Exclude .pyc / .log / .zip files
    if file_path.endswith((".pyc", ".log", ".zip")):
        return True

    return False


def create_release_zip(root_dir, version):
    """Create a zip file of the project."""
    print(f"\n[*] Creating release zip for version {version}...")
    
    releases_dir = os.path.join(root_dir, "releases")
    os.makedirs(releases_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"irorf_v{version}_{timestamp}.zip"
    zip_path = os.path.join(releases_dir, zip_filename)
    
    exclude_patterns = get_exclude_patterns()
    
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(root_dir):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if not should_exclude(os.path.join(root, d), root_dir, exclude_patterns)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if should_exclude(file_path, root_dir, exclude_patterns):
                    continue
                
                # Add file to zip with relative path
                arcname = os.path.relpath(file_path, root_dir)
                zipf.write(file_path, arcname=arcname)
    
    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"[+] Created release: {zip_filename} ({size_mb:.2f} MB)")
    
    return zip_path


def create_commit(root_dir, version):
    """Create a git commit for the version bump."""
    print(f"\n[*] Creating git commit for version {version}...")
    
    # Stage the config file
    returncode, _, stderr = run_command(
        ["git", "add", "utils/config.py"],
        cwd=root_dir
    )
    
    if returncode != 0:
        print(f"[-] Failed to stage file: {stderr}")
        return False
    
    # Create commit
    commit_msg = f"chore: bump version to {version}"
    returncode, stdout, stderr = run_command(
        ["git", "commit", "-m", commit_msg],
        cwd=root_dir
    )
    
    if returncode == 0:
        print(f"[+] Commit created: {commit_msg}")
        return True
    else:
        # Check if there's nothing to commit
        if "nothing to commit" in stderr or "nothing added to commit" in stderr:
            print("[*] No changes to commit")
            return True
        print(f"[-] Failed to create commit: {stderr}")
        return False


def main():
    """Main publishing workflow."""
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    print("=" * 60)
    print("IROpenRelayFinder - PUBLISHING SCRIPT")
    print("=" * 60)
    
    # Step 1: Run smoke tests
    if not run_smoke_test(root_dir):
        print("\n[-] Publishing cancelled due to failed smoke tests.")
        sys.exit(1)
    
    # Step 2: Get current version
    current_version = get_version_from_config(root_dir)
    if not current_version:
        print("[-] Could not determine current version")
        sys.exit(1)
    
    print(f"\n[*] Current version: {current_version}")

    # Step 3: Determine bump type from commit history, then bump
    messages = get_commits_since_last_bump(root_dir)
    bump_type = compute_bump_type(messages)
    new_version = bump_version(current_version, bump_type)

    print(f"[*] Commits since last release: {len(messages)}")
    if messages:
        print("[*] Recent commits:")
        for line in messages[:8]:
            print(f"    {line}")
        if len(messages) > 8:
            print(f"    ... and {len(messages) - 8} more")

    print(f"[*] Bump type: {bump_type.upper()} → {new_version}")
    
    # Step 4: Update version in config
    update_version_in_config(root_dir, new_version)
    
    # Step 5: Create release zip
    zip_path = create_release_zip(root_dir, new_version)
    
    # Step 6: Create commit
    if not create_commit(root_dir, new_version):
        print("[-] Failed to create commit")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("[+] PUBLISHING COMPLETE!")
    print("=" * 60)
    print(f"Release: {os.path.basename(zip_path)}")
    print(f"Version: {new_version}")
    print(f"Location: {zip_path}")
    print("\n[*] Next step: git push (if ready)")
    print("=" * 60)


if __name__ == "__main__":
    main()
