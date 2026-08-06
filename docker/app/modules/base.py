"""Module contract + registry + shared helpers."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable

import httpx

from ..config import HTTP_TIMEOUT, USER_AGENT
from ..schemas import ModuleResult

# name -> module instance
REGISTRY: dict[str, "Module"] = {}


class Module:
    """Subclass and implement `run`.

    `accepts` declares which seed types the module can start from, so the
    orchestrator knows what to dispatch when it pivots onto a new identifier.
    """

    name: str = "unnamed"
    title: str = ""
    accepts: set[str] = set()
    category: str = "misc"
    requires_key: bool = False
    description: str = ""

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:  # pragma: no cover
        raise NotImplementedError

    async def execute(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        started = time.perf_counter()
        try:
            result = await self.run(target, ctx)
        except asyncio.TimeoutError:
            result = ModuleResult(module=self.name, status="error", error="انتهت المهلة")
        except Exception as exc:  # noqa: BLE001 - a broken module must not kill the scan
            result = ModuleResult(module=self.name, status="error", error=f"{type(exc).__name__}: {exc}")
        result.duration = time.perf_counter() - started
        if result.status == "ok" and not result.findings and not result.entities:
            result.status = "empty"
        return result


def register(cls: type[Module]) -> type[Module]:
    instance = cls()
    REGISTRY[instance.name] = instance
    return cls


def modules_for(target_type: str) -> list[Module]:
    return [m for m in REGISTRY.values() if target_type in m.accepts]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def http_client(**kwargs: Any) -> httpx.AsyncClient:
    headers = {"User-Agent": USER_AGENT, **kwargs.pop("headers", {})}
    return httpx.AsyncClient(
        timeout=HTTP_TIMEOUT, headers=headers, follow_redirects=True, **kwargs
    )


async def run_cli(
    argv: list[str],
    timeout: float,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run an external tool, never let it hang the scan."""
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


def safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
