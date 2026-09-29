"""LogIntel Engine CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
import uvicorn
from logintel.config import settings
from logintel.logging import setup_logging


def main():
    parser = argparse.ArgumentParser(description="LogIntel Security Telemetry Analysis Engine")
    parser.add_argument("--host", default=settings.api_host, help="API bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=settings.api_port, help="API port (default: 41721)")
    parser.add_argument("--log-level", default=settings.log_level, help="Log level (DEBUG, INFO, WARNING, ERROR)")
    args = parser.parse_args()

    setup_logging(log_file=settings.log_file, level=args.log_level)
    
    print(f"Starting LogIntel Engine on http://{args.host}:{args.port}")
    uvicorn.run(
        "logintel.api.app:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
