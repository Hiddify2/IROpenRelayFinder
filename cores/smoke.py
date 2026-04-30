import os
import runpy


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    harness_path = os.path.join(root_dir, "scripts", "smoke_harness.py")

    if not os.path.exists(harness_path):
        print(f"[-] Smoke harness not found: {harness_path}")
        return

    runpy.run_path(harness_path, run_name="__main__")
