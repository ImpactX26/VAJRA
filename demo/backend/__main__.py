"""Start the demo API: ``python -m demo.backend [--port 8000]``."""

import argparse
import logging

import uvicorn

from .app import create_app

parser = argparse.ArgumentParser(prog="python -m demo.backend")
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
uvicorn.run(create_app(), host=args.host, port=args.port)
