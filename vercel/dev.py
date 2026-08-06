"""Local dev server.

On Vercel, files in public/ are served by the edge and api/index.py handles
/api/*. Nothing wires those together locally, so this does it:

    pip install -r requirements.txt uvicorn
    python dev.py            # http://127.0.0.1:8000

Not used in production — Vercel never imports this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "api"))

from fastapi.staticfiles import StaticFiles  # noqa: E402
from index import app  # noqa: E402

app.mount("/", StaticFiles(directory=ROOT / "public", html=True), name="public")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
