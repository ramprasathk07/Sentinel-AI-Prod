import subprocess
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from api.routes import webhook, scan, cpg_scan, pentest
from llm.llm_client import llm_client
from storage.db import get_db_path

app = FastAPI(title="Sentinel-AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "null"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(webhook.router, prefix="/webhook", tags=["webhook"])
app.include_router(scan.router, prefix="/api/v1", tags=["scan"])
app.include_router(cpg_scan.router, prefix="/api/v1", tags=["cpg-scan"])
app.include_router(pentest.router, prefix="/api/v1", tags=["pentest"])

_api_dir = Path(__file__).parent.resolve()
_root_dir = _api_dir.parent
_console_dist = _root_dir / "console-ui" / "dist"
_console_assets = _console_dist / "assets"
_landing_dir = _root_dir / "landing"

# Mount the React app build.
if _console_assets.exists():
    app.mount("/assets", StaticFiles(directory=str(_console_assets)), name="assets")
if _landing_dir.exists():
    app.mount("/landing", StaticFiles(directory=str(_landing_dir)), name="landing")


@app.get("/healthz")
async def healthz():
    """Liveness + dependency report. Used by smoke tests and ops dashboards."""
    try:
        llm = await llm_client.health_check()
    except Exception as exc:
        llm = {"healthy": False, "error": str(exc)}
    try:
        git_rev = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(_root_dir),
            stderr=subprocess.DEVNULL,
            timeout=2,
        ).decode().strip()
    except Exception:
        git_rev = "unknown"
    db_path = get_db_path()
    db_exists = Path(db_path).exists()
    payload = {
        "status": "ok" if llm.get("healthy") else "degraded",
        "llm": llm,
        "db": {"path": db_path, "exists": db_exists},
        "git_rev": git_rev,
    }
    return JSONResponse(status_code=200, content=payload)


@app.get("/")
async def root():
    index = _console_dist / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(
        status_code=503,
        content={"message": "console-ui not built. Run `npm --prefix console-ui run build`."},
    )


# SPA fallback: any unmatched non-API path serves index.html so React Router works.
@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    if full_path.startswith(("api/", "webhook/", "assets/", "landing/")):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    index = _console_dist / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse(status_code=503, content={"message": "console-ui dist missing"})
