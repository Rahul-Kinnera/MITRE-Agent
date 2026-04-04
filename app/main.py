from __future__ import annotations

import json
import os
import shutil
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import MitreAnalyzer
from .attack import AttackDataset
from .d3fend import D3fendDataset
from .reporting import write_report


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DATA_DIR = Path(os.environ.get("MITRE_AGENT_DATA_DIR", APP_DIR.parent / "runtime")).resolve()
CACHE_DIR = DATA_DIR / "cache"
REPORTS_DIR = DATA_DIR / "reports"
UPLOADS_DIR = DATA_DIR / "uploads"
ATTACK_CACHE = CACHE_DIR / "attack" / "enterprise-attack.json"
D3FEND_CACHE_DIR = CACHE_DIR / "d3fend"

ATTACK_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
D3FEND_SOURCES = {
    "d3fend-full-mappings.csv": "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv",
    "d3fend-full-mappings.json": "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json",
    "matrix.json": "https://d3fend.mitre.org/api/matrix.json",
    "technique-all.json": "https://d3fend.mitre.org/api/technique/all.json",
    "version.json": "https://d3fend.mitre.org/api/version.json",
}


def ensure_directories() -> None:
    for directory in [CACHE_DIR / "attack", D3FEND_CACHE_DIR, REPORTS_DIR, UPLOADS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


def sync_official_data(force: bool = False) -> dict[str, str]:
    ensure_directories()
    downloads = {}

    _download(ATTACK_SOURCE_URL, ATTACK_CACHE, force)
    downloads["attack_enterprise"] = str(ATTACK_CACHE)

    for filename, url in D3FEND_SOURCES.items():
        destination = D3FEND_CACHE_DIR / filename
        _download(url, destination, force)
        downloads[filename] = str(destination)

    metadata_path = CACHE_DIR / "sync-metadata.json"
    metadata_path.write_text(
        json.dumps(
            {
                "synced_at": datetime.now(timezone.utc).isoformat(),
                "attack_source": ATTACK_SOURCE_URL,
                "d3fend_sources": D3FEND_SOURCES,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    downloads["metadata"] = str(metadata_path)
    return downloads


def _download(url: str, destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        return
    request = urllib.request.Request(url, headers={"User-Agent": "MITRE-Agent/0.1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        destination.write_bytes(response.read())


ATTACK_DATASET = AttackDataset(ATTACK_CACHE)
D3FEND_DATASET = D3fendDataset(D3FEND_CACHE_DIR)
ANALYZER = MitreAnalyzer(ATTACK_DATASET, D3FEND_DATASET)


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_directories()
    if os.environ.get("MITRE_AGENT_AUTO_SYNC", "false").lower() == "true":
        try:
            sync_official_data(force=False)
        except Exception:
            pass
    yield


app = FastAPI(title="MITRE Agent", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/sync")
async def sync(force: bool = False) -> dict[str, object]:
    try:
        result = sync_official_data(force=force)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"MITRE data sync failed: {exc}") from exc
    return {"status": "ok", "downloads": result}


@app.post("/api/analyze")
async def analyze(files: list[UploadFile] = File(...)) -> JSONResponse:
    ensure_directories()
    if not ATTACK_CACHE.exists():
        raise HTTPException(status_code=400, detail="ATT&CK data cache missing. Run MITRE data sync first.")
    if not (D3FEND_CACHE_DIR / "d3fend-full-mappings.csv").exists():
        raise HTTPException(status_code=400, detail="D3FEND cache missing. Run MITRE data sync first.")

    ATTACK_DATASET.load()
    D3FEND_DATASET.load()

    captured_files = []
    for upload in files:
        content = await upload.read()
        if not content:
            continue
        safe_name = Path(upload.filename or f"upload-{uuid.uuid4().hex}.log").name
        destination = UPLOADS_DIR / f"{uuid.uuid4().hex}-{safe_name}"
        destination.write_bytes(content)
        captured_files.append((safe_name, content))

    if not captured_files:
        raise HTTPException(status_code=400, detail="No readable files were uploaded.")

    analysis_id = uuid.uuid4().hex[:12]
    analysis = ANALYZER.analyze_files(captured_files)

    report_dir = REPORTS_DIR / analysis_id
    report_dir.mkdir(parents=True, exist_ok=True)
    write_report(report_dir, analysis_id, analysis)
    navigator_path = report_dir / "attack_layer.json"
    navigator_path.write_text(json.dumps(analysis["navigator_layer"], indent=2), encoding="utf-8")
    raw_path = report_dir / "analysis.json"
    raw_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")

    return JSONResponse(
        {
            "analysis_id": analysis_id,
            **analysis,
            "downloads": {
                "report_html": f"/api/reports/{analysis_id}/report.html",
                "navigator_layer": f"/api/reports/{analysis_id}/attack_layer.json",
                "analysis_json": f"/api/reports/{analysis_id}/analysis.json",
            },
            "navigator_hint_url": "http://localhost:4200/",
        }
    )


@app.get("/api/reports/{analysis_id}/{file_name}")
async def get_report_file(analysis_id: str, file_name: str) -> FileResponse:
    target = (REPORTS_DIR / analysis_id / file_name).resolve()
    base = (REPORTS_DIR / analysis_id).resolve()
    if not str(target).startswith(str(base)) or not target.exists():
        raise HTTPException(status_code=404, detail="Report artifact not found.")
    return FileResponse(target)


@app.post("/api/reports/{analysis_id}/purge")
async def purge_report(analysis_id: str) -> dict[str, str]:
    target = REPORTS_DIR / analysis_id
    if target.exists():
        shutil.rmtree(target)
    return {"status": "deleted"}
