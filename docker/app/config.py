"""Runtime configuration. Everything optional degrades gracefully."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # dotenv is optional
    pass

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "osint.db"

# --- API keys (all optional) -------------------------------------------------
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()
NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "").strip()

# --- Behaviour ---------------------------------------------------------------
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "15"))
MODULE_TIMEOUT = float(os.getenv("MODULE_TIMEOUT", "180"))
MAX_CONCURRENT_MODULES = int(os.getenv("MAX_CONCURRENT_MODULES", "6"))
MAX_PIVOTS = int(os.getenv("MAX_PIVOTS", "3"))
USER_AGENT = os.getenv("USER_AGENT", "osint-suite/1.0 (self-hosted research)")

DISABLED_MODULES = {
    m.strip() for m in os.getenv("DISABLED_MODULES", "").split(",") if m.strip()
}

# --- External CLI tools ------------------------------------------------------
# The Docker image installs each of these in its own virtualenv to avoid
# dependency conflicts. Outside Docker we fall back to whatever is on PATH.
_VENV_ROOT = Path(os.getenv("VENV_ROOT", "/opt/venvs"))


def find_tool(name: str) -> str | None:
    candidate = _VENV_ROOT / name / "bin" / name
    if candidate.exists():
        return str(candidate)
    env_override = os.getenv(f"{name.upper()}_BIN", "").strip()
    if env_override and Path(env_override).exists():
        return env_override
    return shutil.which(name)


TOOLS = {name: find_tool(name) for name in ("holehe", "maigret", "ghunt", "sherlock")}

GHUNT_CREDS = Path(os.getenv("GHUNT_CREDS", Path.home() / ".malfrats/ghunt/creds.m"))
