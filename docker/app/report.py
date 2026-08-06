"""Renders a self-contained, printable HTML report for a finished scan."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import BASE_DIR

_env = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html"]),
)

CATEGORY_LABELS = {
    "identity": "الهوية",
    "accounts": "الحسابات",
    "breaches": "التسريبات",
    "phone": "الهاتف",
    "google": "Google",
    "infra": "البنية التحتية",
    "misc": "أخرى",
}

SEVERITY_ORDER = {"high": 0, "notable": 1, "info": 2}


def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "—"
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def render_report(job: dict[str, Any]) -> str:
    payload = job.get("payload", {})
    findings = payload.get("findings", [])

    grouped: dict[str, list[dict]] = {}
    for f in findings:
        grouped.setdefault(f.get("category", "misc"), []).append(f)
    for items in grouped.values():
        items.sort(key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "info"), 3),
                                  -float(x.get("confidence", 0))))

    ordered = [
        (CATEGORY_LABELS.get(k, k), grouped[k])
        for k in ["identity", "accounts", "breaches", "google", "phone", "infra", "misc"]
        if k in grouped
    ]

    template = _env.get_template("report.html")
    return template.render(
        job=job,
        summary=payload.get("summary", {}),
        groups=ordered,
        modules=payload.get("modules", []),
        entities=payload.get("entities", []),
        graph_json=json.dumps(payload.get("graph", {}), ensure_ascii=False),
        created=_fmt_time(job.get("created_at")),
        finished=_fmt_time(job.get("updated_at")),
        elapsed=payload.get("elapsed", 0),
        generated=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
    )
