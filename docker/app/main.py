"""FastAPI entry point."""
from __future__ import annotations

import asyncio
import json
from typing import Any, Literal

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db
from .config import BASE_DIR, TOOLS
from .orchestrator import detect_type, module_catalog, run_scan
from .report import render_report

app = FastAPI(title="OSINT Suite", version="1.0", docs_url="/api/docs")

STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def _startup() -> None:
    db.init()


class ScanRequest(BaseModel):
    target: str = Field(min_length=2, max_length=320)
    target_type: Literal["auto", "email", "username", "phone", "domain"] = "auto"
    pivot: bool = True
    modules: list[str] | None = None
    top_sites: int = Field(default=500, ge=50, le=3000)
    region: str | None = None


@app.get("/", response_class=HTMLResponse)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/modules")
async def api_modules() -> dict[str, Any]:
    return {
        "modules": module_catalog(),
        "tools": {k: bool(v) for k, v in TOOLS.items()},
    }


@app.post("/api/scan")
async def api_scan(req: ScanRequest, background: BackgroundTasks) -> dict[str, str]:
    target = req.target.strip()
    ttype = req.target_type if req.target_type != "auto" else detect_type(target)
    options: dict[str, Any] = {
        "pivot": req.pivot,
        "modules": req.modules,
        "top_sites": req.top_sites,
        "region": req.region,
    }
    job_id = db.create_job(target, ttype, options)
    background.add_task(_launch, job_id, target, ttype, options)
    return {"job_id": job_id, "target_type": ttype}


def _launch(job_id: str, target: str, ttype: str, options: dict[str, Any]) -> None:
    try:
        asyncio.run(run_scan(job_id, target, ttype, options))
    except Exception as exc:  # noqa: BLE001
        job = db.get_job(job_id) or {}
        payload = job.get("payload", {})
        payload.setdefault("log", []).append({"level": "error", "msg": str(exc)})
        db.update_job(job_id, status="error", payload=payload)


@app.get("/api/scan/{job_id}")
async def api_job(job_id: str) -> dict[str, Any]:
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "المهمة غير موجودة")
    return job


@app.get("/api/scans")
async def api_jobs(limit: int = 25) -> dict[str, Any]:
    return {"jobs": db.list_jobs(limit)}


@app.delete("/api/scan/{job_id}")
async def api_delete(job_id: str) -> dict[str, bool]:
    return {"deleted": db.delete_job(job_id)}


@app.get("/api/scan/{job_id}/report.json")
async def api_report_json(job_id: str) -> Response:
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "المهمة غير موجودة")
    body = json.dumps(job, ensure_ascii=False, indent=2)
    return Response(
        body, media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="osint-{job_id}.json"'},
    )


@app.get("/api/scan/{job_id}/report.html", response_class=HTMLResponse)
async def api_report_html(job_id: str) -> HTMLResponse:
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "المهمة غير موجودة")
    return HTMLResponse(render_report(job))


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True, "tools": {k: bool(v) for k, v in TOOLS.items()}})
