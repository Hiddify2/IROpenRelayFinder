#!/usr/bin/env python3
"""
IROpenRelayFinder - UNIVERSAL LAUNCHER
This file is designed to be completely agnostic to the underlying core logic.
It sets up the OS environment, applies low-level async optimizations, and
dynamically imports and executes external core modules.
"""

import sys
import os
import argparse
import importlib
import asyncio
import logging
from functools import wraps

def optimize_os_environment():
    """Applies necessary async and socket limits based on the host OS."""
    
    # ---------------------------------------------------------
    # 1. WINDOWS OPTIMIZATIONS & BUG FIXES
    # ---------------------------------------------------------
    if sys.platform == 'win32':
        # Enable Proactor to bypass the 512 socket limit on Windows
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        
        # Patch the infamous asyncio [WinError 10054] ghost traceback bug
        try:
            from asyncio.proactor_events import _ProactorBasePipeTransport
            def silence_winerror_10054(func):
                @wraps(func)
                def wrapper(self, *args, **kwargs):
                    try:
                        return func(self, *args, **kwargs)
                    except (ConnectionAbortedError, ConnectionResetError):
                        pass
                return wrapper
            _ProactorBasePipeTransport._call_connection_lost = silence_winerror_10054(
                _ProactorBasePipeTransport._call_connection_lost
            )
        except ImportError:
            pass

    # ---------------------------------------------------------
    # 2. LINUX / MACOS OPTIMIZATIONS
    # ---------------------------------------------------------
    else:
        # Attempt to use the ultra-fast uvloop C-extension if installed
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            pass
            
        # Attempt to lift the default 1024 file descriptor (socket) limit
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = 65535
            if hard != resource.RLIM_INFINITY and target > hard:
                target = hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        except Exception:
            pass

def launch_core(core_name, forward_args):
    """
    Dynamically loads a python file from the 'cores/' directory and executes it.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cores_dir = os.path.join(base_dir, "cores")
    utils_dir = os.path.join(base_dir, "utils")
    
    # Ensure our required directories exist
    os.makedirs(cores_dir, exist_ok=True)
    os.makedirs(utils_dir, exist_ok=True)
        
    # Inject the base directory into Python's path so modules can import utils natively
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
    
    module_path = f"cores.{core_name}"
    
    try:
        # Dynamically import the requested core
        core_module = importlib.import_module(module_path)
        
        # Pass unknown sys.argv arguments down to the core so it can parse its own flags
        sys.argv = [sys.argv[0]] + forward_args
        
        # Standardized Execution Interfaces
        if hasattr(core_module, 'main'):
            # Standard synchronous entry point
            core_module.main()
        elif hasattr(core_module, 'run'):
            # Standard asynchronous entry point
            asyncio.run(core_module.run())
        else:
            print(f"[-] ERROR: '{core_name}.py' is missing a 'main()' or 'run()' function.")
            print(f"[*] Please ensure your core file has an entry point.")
            sys.exit(1)
            
    except ModuleNotFoundError as e:
        print(f"[-] ERROR: Could not find core '{core_name}' or a dependency: {e}")
        print(f"[*] Please ensure 'cores/{core_name}.py' exists.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Execution interrupted by user. Exiting safely...")
        sys.exit(0)
    except Exception as e:
        logging.basicConfig(level=logging.ERROR)
        logging.error(f" FATAL CRASH in core '{core_name}':", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    # Setup a flexible CLI parser that ignores arguments it doesn't recognize
    parser = argparse.ArgumentParser(
        description="IROpenRelayFinder - Modular Execution Engine",
        add_help=False # Disable default help so we can forward `-h` to the core
    )
    
    # We default to 'ui' if nothing is passed: `python main.py`
    parser.add_argument(
        "--core", "-c", 
        type=str, 
        default="ui", 
        help="Specify which core module to execute (default: ui)"
    )
    
    # Parse our known arguments, and bundle everything else to send to the core
    known_args, unknown_args = parser.parse_known_args()
    
    # Bootstrap OS
    optimize_os_environment()
    
    # Hand off execution
    launch_core(known_args.core, unknown_args)
