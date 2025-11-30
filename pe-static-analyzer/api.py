"""
Minimal FastAPI wrapper for PE Static Analyzer.
Endpoints:
  - POST /analyze (upload file)
  - POST /analyze-path (analyze local path)
  - POST /scan-dir (recursive directory scan)
  - POST /yara-sync (sync rules)
  - GET /status (basic health)

Run:
  uvicorn api:app --reload --host 0.0.0.0 --port 8000
"""

import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from src.core.analyzer import PEStaticAnalyzer
from src.modules import create_default_modules
from src.utils.yara_sync import sync_yara_rules

app = FastAPI(title="PE Static Analyzer API", version="1.0.0")

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_analyzer() -> PEStaticAnalyzer:
    analyzer = PEStaticAnalyzer()
    for m in create_default_modules():
        analyzer.plugin_manager.register_module(m)
    return analyzer


@app.get("/status")
def status():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    analyzer = _get_analyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        dest = Path(tmpdir) / file.filename
        data = await file.read()
        dest.write_bytes(data)
        res = analyzer.analyze_file(str(dest))
        return JSONResponse(res.to_dict())


@app.post("/analyze-path")
def analyze_path(path: str = Form(...)):
    analyzer = _get_analyzer()
    target = Path(path)
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=400, detail="Calea nu este un fisier valid")
    res = analyzer.analyze_file(str(target))
    return JSONResponse(res.to_dict())


@app.post("/scan-dir")
def scan_dir(path: str = Form(...), recursive: bool = Form(True)):
    analyzer = _get_analyzer()
    directory = Path(path)
    if not directory.is_dir():
        raise HTTPException(status_code=400, detail="Director invalid")
    files: List[Path] = [p for p in directory.rglob("*") if p.is_file()] if recursive else list(directory.iterdir())
    results = []
    for p in files:
        try:
            res = analyzer.analyze_file(str(p))
            results.append(res.to_dict())
        except Exception:
            # continue on error
            continue
    return {"count": len(results), "results": results}


@app.post("/yara-sync")
def yara_sync(owner: Optional[str] = Form(None), repo: Optional[str] = Form(None), token: Optional[str] = Form(None)):
    saved = sync_yara_rules(owner=owner or None, repo=repo or None, token=token or "")
    return {"saved": saved}
