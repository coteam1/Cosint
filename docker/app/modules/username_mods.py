"""Username-seeded modules."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..config import MODULE_TIMEOUT, TOOLS
from ..schemas import (
    CONF_CONFIRMED, CONF_WEAK, Edge, Entity, Finding, ModuleResult, make_id,
)
from .base import Module, register, run_cli, safe_json


@register
class Maigret(Module):
    name = "maigret"
    title = "maigret — الحسابات باسم المستخدم"
    accepts = {"username"}
    category = "accounts"
    description = "يبحث عن نفس اسم المستخدم عبر آلاف المنصّات"

    async def run(self, target: str, ctx: dict[str, Any]) -> ModuleResult:
        res = ModuleResult(module=self.name)
        binary = TOOLS.get("maigret")
        if not binary:
            return await _sherlock_fallback(self.name, target, res)

        username = target.strip()
        uid = make_id("username", username)
        # A username match is never proof of identity - the person who owns
        # alice@example.com is not necessarily the "alice" on every platform.
        base_conf = float(ctx.get("seed_confidence", CONF_CONFIRMED))
        conf = min(base_conf, CONF_WEAK if ctx.get("derived") else CONF_CONFIRMED)

        with tempfile.TemporaryDirectory() as tmp:
            argv = [
                binary, username, "--json", "simple", "--folderoutput", tmp,
                "--timeout", "20", "--retries", "1", "--no-progressbar",
                "--no-color", "--top-sites", str(ctx.get("top_sites", 500)),
            ]
            try:
                await run_cli(argv, timeout=MODULE_TIMEOUT, cwd=tmp)
            except Exception as exc:  # noqa: BLE001
                res.status = "error"
                res.error = str(exc)[:300]
                return res
            data = _load_maigret_report(Path(tmp))

        if data is None:
            res.note = "لم يُنتج maigret تقريراً"
            return res

        for site, info in data.items():
            if not isinstance(info, dict):
                continue
            status = ((info.get("status") or {}).get("status") or "").lower()
            url = info.get("url_user") or info.get("url")
            if status not in {"claimed", "found"} or not url:
                continue

            a = Entity(type="account", value=url, label=site, source=self.name,
                       confidence=conf, url=url, meta={"service": site})
            res.entities.append(a)
            res.edges.append(Edge(uid, a.id, "profile_on", conf, self.name))

            ids = (info.get("status") or {}).get("ids") or {}
            extra = []
            for key, label in (("fullname", "الاسم"), ("username", "المعرّف"),
                               ("location", "الموقع"), ("created_at", "أُنشئ في")):
                if ids.get(key):
                    extra.append(f"{label}: {ids[key]}")
            if ids.get("fullname"):
                p = Entity(type="person", value=str(ids["fullname"]), source=f"{self.name}:{site}",
                           confidence=conf)
                res.entities.append(p)
                res.edges.append(Edge(a.id, p.id, "displays_name", conf, self.name))

            res.findings.append(Finding(
                module=self.name, category="accounts",
                title=f"{site} — @{username}", detail=" · ".join(extra),
                url=url, confidence=conf,
                severity="notable" if extra else "info",
                raw={"site": site, "ids": ids},
            ))

        if res.findings:
            res.findings.insert(0, Finding(
                module=self.name, category="accounts",
                title=f"عُثر على {len(res.findings)} ملفاً باسم @{username}",
                detail=("درجة الثقة منخفضة لأن اسم المستخدم مُشتق من البريد ولم يُؤكَّد"
                        if ctx.get("derived") else ""),
                confidence=conf,
            ))
        return res


def _load_maigret_report(folder: Path) -> dict | None:
    candidates = sorted(folder.rglob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data:
            return data
    return None


async def _sherlock_fallback(module_name: str, username: str, res: ModuleResult) -> ModuleResult:
    binary = TOOLS.get("sherlock")
    if not binary:
        res.status = "not_configured"
        res.note = "maigret و sherlock غير مثبّتين"
        return res

    uid = make_id("username", username)
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp) / "out.txt"
        argv = [binary, username, "--print-found", "--timeout", "15", "--output", str(out_file)]
        try:
            _, out, _ = await run_cli(argv, timeout=MODULE_TIMEOUT, cwd=tmp)
        except Exception as exc:  # noqa: BLE001
            res.status = "error"
            res.error = str(exc)[:300]
            return res
        text = out_file.read_text(errors="replace") if out_file.exists() else out

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("http"):
            continue
        a = Entity(type="account", value=line, label=line.split("/")[2], source="sherlock",
                   confidence=CONF_WEAK, url=line)
        res.entities.append(a)
        res.edges.append(Edge(uid, a.id, "profile_on", CONF_WEAK, "sherlock"))
        res.findings.append(Finding(
            module=module_name, category="accounts",
            title=f"{a.label} — @{username}", url=line, confidence=CONF_WEAK,
        ))
    res.note = "استُخدم sherlock كبديل"
    return res
