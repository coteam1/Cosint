"""Turns the entity/edge store into a Cytoscape-ready graph."""
from __future__ import annotations

from typing import Any

from .schemas import Edge, Entity, make_id

TYPE_LABELS = {
    "email": "بريد", "username": "اسم مستخدم", "phone": "هاتف", "domain": "نطاق",
    "person": "اسم", "account": "حساب", "breach": "تسريب", "image": "صورة",
    "url": "رابط", "gaia_id": "Google", "location": "موقع",
}


def build_graph(entities: list[Entity], edges: list[Edge], target: str, target_type: str) -> dict[str, Any]:
    seed_id = make_id(target_type, target.strip())
    known = {e.id for e in entities}

    nodes = []
    for e in entities:
        degree = sum(1 for x in edges if x.source == e.id or x.target == e.id)
        nodes.append({
            "data": {
                "id": e.id,
                "label": _trim(e.label or e.value),
                "full": e.value,
                "type": e.type,
                "typeLabel": TYPE_LABELS.get(e.type, e.type),
                "confidence": round(e.confidence, 2),
                "source": e.source,
                "url": e.url,
                "seed": e.id == seed_id,
                "degree": degree,
                "corroboration": e.meta.get("corroboration", 1),
            }
        })

    links = []
    for x in edges:
        if x.source not in known or x.target not in known:
            continue
        links.append({
            "data": {
                "id": x.id, "source": x.source, "target": x.target,
                "label": x.relation, "confidence": round(x.confidence, 2),
                "module": x.module,
            }
        })

    return {"nodes": nodes, "edges": links, "seed": seed_id, "stats": _stats(entities)}


def _stats(entities: list[Entity]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in entities:
        out[e.type] = out.get(e.type, 0) + 1
    return out


def _trim(text: str, limit: int = 32) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"
