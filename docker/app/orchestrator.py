"""Runs modules, merges their output, and pivots onto newly found identifiers."""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from . import db
from .config import DISABLED_MODULES, MAX_CONCURRENT_MODULES, MAX_PIVOTS, MODULE_TIMEOUT
from .graph import build_graph
from .modules import REGISTRY, modules_for
from .schemas import CONF_DERIVED, Edge, Entity, Finding, ModuleResult, make_id

PIVOTABLE = ("username", "phone", "domain")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{6,}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


def detect_type(target: str) -> str:
    t = target.strip()
    if EMAIL_RE.match(t):
        return "email"
    if PHONE_RE.match(t.replace(" ", "")):
        return "phone"
    if DOMAIN_RE.match(t):
        return "domain"
    return "username"


class Store:
    """Deduplicating collector. Same identifier from two modules = one node."""

    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.edges: dict[str, Edge] = {}
        self.findings: list[Finding] = []
        self.module_reports: list[dict[str, Any]] = []
        self.log: list[dict[str, Any]] = []

    def add_entity(self, e: Entity) -> None:
        existing = self.entities.get(e.id)
        if existing is None:
            self.entities[e.id] = e
            return
        # keep the strongest claim, and remember every source that agreed
        sources = set(filter(None, [existing.source, e.source]))
        if e.confidence > existing.confidence:
            e.meta = {**existing.meta, **e.meta}
            self.entities[e.id] = e
        else:
            existing.meta.update(e.meta)
        self.entities[e.id].meta["sources"] = sorted(sources)
        self.entities[e.id].meta["corroboration"] = len(sources)

    def add_edge(self, edge: Edge) -> None:
        prev = self.edges.get(edge.id)
        if prev is None or edge.confidence > prev.confidence:
            self.edges[edge.id] = edge

    def absorb(self, result: ModuleResult) -> None:
        for e in result.entities:
            self.add_entity(e)
        for edge in result.edges:
            self.add_edge(edge)
        self.findings.extend(result.findings)
        self.module_reports.append(result.to_dict())

    def snapshot(self) -> dict[str, Any]:
        return {
            "entities": [e.to_dict() for e in self.entities.values()],
            "edges": [x.to_dict() for x in self.edges.values()],
            "findings": [f.to_dict() for f in self.findings],
            "modules": self.module_reports,
            "log": self.log,
        }


async def run_scan(job_id: str, target: str, target_type: str, options: dict[str, Any]) -> None:
    store = Store()
    started = time.time()
    enabled: set[str] | None = set(options.get("modules") or []) or None

    def note(text: str, level: str = "info") -> None:
        store.log.append({"t": round(time.time() - started, 2), "level": level, "msg": text})

    def persist(status: str) -> None:
        payload = store.snapshot()
        payload["options"] = options
        payload["target"] = target
        payload["target_type"] = target_type
        payload["elapsed"] = round(time.time() - started, 2)
        payload["graph"] = build_graph(
            list(store.entities.values()), list(store.edges.values()), target, target_type
        )
        payload["summary"] = summarise(store, target, target_type)
        db.update_job(job_id, status=status, payload=payload)

    db.update_job(job_id, status="running")

    # Seed node
    seed = Entity(type=target_type, value=target.strip(), source="input", confidence=1.0,
                  meta={"seed": True})
    store.add_entity(seed)
    note(f"بدء الفحص على {target} كنوع {target_type}")
    persist("running")

    sem = asyncio.Semaphore(MAX_CONCURRENT_MODULES)

    async def guarded(mod, value: str, ctx: dict[str, Any]) -> ModuleResult:
        async with sem:
            note(f"تشغيل {mod.name} على {value}")
            try:
                return await asyncio.wait_for(mod.execute(value, ctx), timeout=MODULE_TIMEOUT + 15)
            except asyncio.TimeoutError:
                return ModuleResult(module=mod.name, status="error", error="تجاوز المهلة الكلية")

    # ---- wave 1: everything that accepts the seed type ---------------------
    wave1 = [m for m in modules_for(target_type)
             if m.name not in DISABLED_MODULES and (enabled is None or m.name in enabled)]
    if not wave1:
        note("لا توجد وحدات مطابقة لهذا النوع", "warn")

    results = await asyncio.gather(*(guarded(m, target, dict(options)) for m in wave1))
    for r in results:
        store.absorb(r)
        note(f"{r.module}: {r.status} ({len(r.findings)} نتيجة) في {r.duration:.1f}ث",
             "warn" if r.status == "error" else "info")
    persist("running")

    # ---- wave 2: pivot onto discovered identifiers -------------------------
    if options.get("pivot", True):
        pivots = pick_pivots(store, target_type)
        if pivots:
            note(f"محاور جديدة: " + "، ".join(f"{e.type}={e.value}" for e in pivots))
        tasks = []
        for ent in pivots:
            for mod in modules_for(ent.type):
                if mod.name in DISABLED_MODULES or (enabled is not None and mod.name not in enabled):
                    continue
                ctx = dict(options)
                ctx["derived"] = ent.confidence < 1.0
                ctx["seed_confidence"] = ent.confidence
                tasks.append(guarded(mod, ent.value, ctx))
        if tasks:
            for r in await asyncio.gather(*tasks):
                store.absorb(r)
                note(f"{r.module} (محور): {r.status} ({len(r.findings)} نتيجة)")

    note(f"اكتمل الفحص في {time.time() - started:.1f} ثانية")
    persist("done")


def pick_pivots(store: Store, seed_type: str) -> list[Entity]:
    candidates = [
        e for e in store.entities.values()
        if e.type in PIVOTABLE and e.type != seed_type and not e.meta.get("seed")
    ]
    # strongest claims first, and never chase more than MAX_PIVOTS
    candidates.sort(key=lambda e: (-e.confidence, e.type))
    picked: list[Entity] = []
    seen_types: dict[str, int] = {}
    for e in candidates:
        if e.confidence < CONF_DERIVED:
            continue
        if seen_types.get(e.type, 0) >= 2:
            continue
        picked.append(e)
        seen_types[e.type] = seen_types.get(e.type, 0) + 1
        if len(picked) >= MAX_PIVOTS:
            break
    return picked


def summarise(store: Store, target: str, target_type: str) -> dict[str, Any]:
    by_cat: dict[str, int] = {}
    for f in store.findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1

    accounts = [e for e in store.entities.values() if e.type == "account"]
    breaches = [e for e in store.entities.values() if e.type == "breach"]
    names = [e for e in store.entities.values() if e.type == "person"]
    phones = [e for e in store.entities.values() if e.type == "phone"]

    high = [f for f in store.findings if f.severity == "high"]
    corroborated = [e for e in store.entities.values() if e.meta.get("corroboration", 0) > 1]

    # A crude but honest exposure score: breaches and leaked identifiers weigh
    # most, raw account count least.
    score = min(100, len(breaches) * 12 + len(high) * 6 + len(accounts) * 2 + len(names) * 5)

    return {
        "target": target,
        "target_type": target_type,
        "counts": {
            "entities": len(store.entities),
            "findings": len(store.findings),
            "accounts": len(accounts),
            "breaches": len(breaches),
            "names": len(names),
            "phones": len(phones),
            "high_severity": len(high),
            "corroborated": len(corroborated),
        },
        "by_category": by_cat,
        "exposure_score": score,
        "names": sorted({e.value for e in names}),
        "top_accounts": [
            {"service": e.label, "url": e.url, "confidence": e.confidence}
            for e in sorted(accounts, key=lambda x: -x.confidence)[:40]
        ],
        "breaches": sorted({e.value for e in breaches}),
    }


def module_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": m.name, "title": m.title or m.name, "accepts": sorted(m.accepts),
            "category": m.category, "description": m.description,
            "enabled": m.name not in DISABLED_MODULES,
        }
        for m in sorted(REGISTRY.values(), key=lambda x: (x.category, x.name))
    ]
