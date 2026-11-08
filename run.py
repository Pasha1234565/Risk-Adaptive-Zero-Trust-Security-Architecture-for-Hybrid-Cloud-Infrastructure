"""Local launcher for the zero-trust prototype.

Usage:
    python run.py                 # http://127.0.0.1:8000
    python run.py --port 9000
    python run.py --reload        # development auto-reload
    python run.py --open          # open the browser after startup
"""

from __future__ import annotations

import argparse
import os
import threading
import webbrowser

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the hybrid-cloud zero-trust prototype.")
    parser.add_argument("--host", default=os.environ.get("ZT_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ZT_PORT", "8000")))
    parser.add_argument("--reload", action="store_true", help="Restart when Python files change")
    parser.add_argument("--open", action="store_true", help="Open the console in the default browser")
    parser.add_argument(
        "--log-level",
        default=os.environ.get("ZT_LOG_LEVEL", "info"),
        choices=["critical", "error", "warning", "info", "debug", "trace"],
    )
    args = parser.parse_args()

    if args.open:
        host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{args.port}/login")).start()

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
