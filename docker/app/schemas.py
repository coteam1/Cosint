"""Normalised data model shared by every module.

Everything a module discovers is expressed as Entities (nodes), Edges
(relations) and Findings (human-readable rows). That uniformity is what makes
a single correlated report possible.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

EntityType = Literal[
    "email", "username", "phone", "domain", "person",
    "account", "breach", "image", "url", "gaia_id", "location",
]

# Confidence conventions - keep these honest, they are the main guard against
# building a dossier on the wrong human being.
CONF_CONFIRMED = 1.0   # the source explicitly returned this identifier
CONF_STRONG = 0.8      # near-certain, e.g. Gravatar profile tied to the hash
CONF_DERIVED = 0.5     # inferred, e.g. username taken from the email local part
CONF_WEAK = 0.3        # plausible only, e.g. same handle on an unrelated site


def make_id(etype: str, value: str) -> str:
    """Deterministic id so two modules finding the same thing collapse into one node."""
    key = f"{etype}:{value.strip().lower()}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class Entity:
    type: EntityType
    value: str
    label: str = ""
    confidence: float = CONF_CONFIRMED
    source: str = ""
    url: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = make_id(self.type, self.value)
        if not self.label:
            self.label = self.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    source: str          # entity id
    target: str          # entity id
    relation: str        # "has_account", "derived_from", "leaked_in", ...
    confidence: float = CONF_CONFIRMED
    module: str = ""

    @property
    def id(self) -> str:
        return f"{self.source}->{self.target}:{self.relation}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        return d


@dataclass
class Finding:
    module: str
    category: str        # accounts | breaches | identity | phone | google | infra
    title: str
    detail: str = ""
    url: str | None = None
    confidence: float = CONF_CONFIRMED
    severity: Literal["info", "notable", "high"] = "info"
    raw: dict[str, Any] = field(default_factory=dict)
    seen_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    status: Literal["ok", "empty", "error", "skipped", "not_configured"] = "ok"
    entities: list[Entity] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "error": self.error,
            "duration": round(self.duration, 2),
            "note": self.note,
            "counts": {
                "entities": len(self.entities),
                "findings": len(self.findings),
            },
        }
