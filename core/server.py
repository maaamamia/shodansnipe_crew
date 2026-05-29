"""
server.py — FastAPI server for ShodanSnipe.

Run:   uvicorn server:app --reload
Then open http://127.0.0.1:8000

Bug fixes applied (auditor pass):
  BUG-1  _current_tier assigned without 'global' in health() and set_api_key()
         → tier was always "free" regardless of actual plan.
  BUG-2  _last_search_id assigned without 'global' in search() and bulk()
         → search_id was silently discarded; _ensure_results() fallback
           always failed; AI triage endpoints had no results to work on.
  BUG-3  WorkspaceSaveIn defined twice — second definition (name+notes only)
         silently shadowed the first (with description/query/session_id/tags).
         Removed the duplicate; only the full-featured model survives.
  BUG-4  /api/workspaces routes called db.workspace_list/save/load/delete
         which do not exist in db.py → AttributeError at runtime.
         Replaced with inline SQL (same pattern as /api/workspace/* routes
         already in the file) using _ensure_workspace_schema().
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import sys
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Any

from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import db
from shodansnipe_core import ShodanQuery, serialize_result, DataValidator
from scope import Scope, apply_scope, audit
from diff_store import save_snapshot, diff
from query_advisor import FILTER_REFERENCE, TEMPLATES, render_template, suggest_followups
import threat_feeds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Passphrase + DB init
# ---------------------------------------------------------------------------
def _get_passphrase() -> str:
    pw = os.environ.get("SHODANSNIPE_PASSPHRASE", "").strip()
    if pw:
        logger.info("Passphrase loaded from SHODANSNIPE_PASSPHRASE env var")
        return pw
    if not sys.stdin.isatty():
        logger.error("No passphrase via env and stdin is not a TTY. Cannot prompt.")
        sys.exit("Set SHODANSNIPE_PASSPHRASE or run interactively.")
    print("\nShodanSnipe — encrypted DB passphrase required.")
    print("(First run? Pick a strong one and remember it. There is no recovery.)\n")
    return getpass.getpass("Passphrase: ")


_passphrase = _get_passphrase()
try:
    db.init(_passphrase)
except ValueError as e:
    sys.exit(f"Database init failed: {e}")
del _passphrase

logger.info("=" * 60)
logger.info("  ShodanSnipe — server.py (auditor-fixed build)")
logger.info("  Fixes: BUG-1 tier global, BUG-2 search_id global,")
logger.info("         BUG-3 duplicate WorkspaceSaveIn, BUG-4 missing db.workspace_*")
logger.info("=" * 60)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="ShodanSnipe", version="1.1.0")

from fastapi import Request
from fastapi.exceptions import RequestValidationError


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(status_code=500, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


# ---------------------------------------------------------------------------
# Module-level mutable state
# All variables mutated inside route functions MUST be declared global there.
# ---------------------------------------------------------------------------
_engine: ShodanQuery | None = None
_current_scope: Scope = Scope(name="(none)")
_last_results: list[dict] = []
_last_query: str = ""
_last_search_id: int | None = None
# BUG-1 FIX: _current_tier is a module-level str. Functions that assign to it
# must declare 'global _current_tier', otherwise Python creates a local variable
# and the module-level value never changes. Fixed in health() and set_api_key().
_current_tier: str = "free"

# Live search progress — updated by /api/search, polled by the UI
_search_progress: dict = {"phase": "idle", "found": 0, "total": 0, "query": ""}

def _ensure_results() -> bool:
    """
    Lazy-load results from DB if the in-memory list was lost (e.g. server restart).
    Returns True when results are available.
    """
    # BUG-2 NOTE: this function reads _last_search_id. That value is only populated
    # correctly now that search() and bulk() declare 'global _last_search_id'.
    global _last_results, _last_query
    if _last_results:
        return True
    if _last_search_id is not None:
        record = db.search_load(_last_search_id)
        if record and record.get("results"):
            _last_results = record["results"]
            _last_query = record.get("query", _last_query)
            logger.info(
                "Reloaded %d results from search_id=%s",
                len(_last_results), _last_search_id,
            )
            return True
    history = db.search_history(limit=1)
    if history:
        record = db.search_load(history[0]["id"])
        if record and record.get("results"):
            _last_results = record["results"]
            _last_query = record.get("query", "")
            logger.info("Auto-restored results from last search (id=%s)", history[0]["id"])
            return True
    return False


def _get_engine() -> ShodanQuery:
    global _engine
    if _engine is None:
        key = db.get_config("shodan_api_key")
        if not key:
            raise HTTPException(503, "No Shodan API key set. POST one to /api/config/api-key.")
        _engine = ShodanQuery(key)
    return _engine


def _reset_engine() -> None:
    global _engine
    _engine = None


# ---------------------------------------------------------------------------
# Workspace schema helper (used by both /api/workspace and /api/workspaces)
# ---------------------------------------------------------------------------
_WORKSPACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    query            TEXT NOT NULL DEFAULT '',
    search_id        INTEGER,
    notes            TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    session_id       TEXT NOT NULL DEFAULT '',
    results_snapshot TEXT NOT NULL DEFAULT '',
    panel_layout     TEXT NOT NULL DEFAULT '',
    tags             TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL
);
"""


def _ensure_workspace_schema() -> None:
    with db._lock:
        db._c().executescript(_WORKSPACE_SCHEMA)
        db._c().commit()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ScopeIn(BaseModel):
    name: str = "default"
    cidrs: list[str] = []
    domains: list[str] = []
    asns: list[str] = []
    orgs: list[str] = []


class SearchIn(BaseModel):
    query: str
    limit: int = Field(25, ge=1, le=500)
    enrich: bool = False
    tags: Optional[list[str]] = None
    override_scope: bool = False
    override_reason: str = ""


class BulkIn(BaseModel):
    ips: list[str]
    enrich: bool = False
    override_scope: bool = False
    override_reason: str = ""


class TemplateRenderIn(BaseModel):
    template_id: str
    params: dict[str, str] = {}


class SaveIn(BaseModel):
    label: str
    query: str
    watched: bool = False


class DiffIn(BaseModel):
    query: str
    limit: int = Field(25, ge=1, le=500)
    enrich: bool = False
    override_scope: bool = False
    override_reason: str = ""
    save_snapshot: bool = True


class SuggestIn(BaseModel):
    query: str


class ApiKeyIn(BaseModel):
    api_key: str


class GoalIn(BaseModel):
    goal: str
    provider: Optional[str] = None
    tier: Optional[str] = None          # 'free' | 'member' | 'enterprise'
    num_queries: int = 6                 # how many queries the analyst wants
    analyst_guidance: Optional[str] = None  # persistent analyst preferences/context
    save_guidance: bool = False          # if True, persist guidance to DB


# BUG-3 FIX: only ONE WorkspaceSaveIn model. The original server.py defined
# this twice — the second definition (name + notes only) shadowed the first,
# silently dropping description, query, session_id, results_snapshot,
# panel_layout, and tags from every POST to /api/workspaces.
class WorkspaceSaveIn(BaseModel):
    name: str
    description: str = ""
    query: str = ""
    session_id: str = ""
    results_snapshot: str = ""
    panel_layout: str = ""
    tags: str = ""
    notes: str = ""  # merged from the duplicate definition


class LLMSettingsIn(BaseModel):
    provider: str
    model: str
    endpoint: Optional[str] = None
    anthropic_key: Optional[str] = None
    openai_key: Optional[str] = None


class TriageIn(BaseModel):
    provider: Optional[str] = None
    persona: Optional[str] = "asm"


class ExplainHostIn(BaseModel):
    ip: str
    provider: Optional[str] = None


class AskIn(BaseModel):
    question: str
    query: str = ""                    # current query context
    tier: Optional[str] = None
    analyst_guidance: Optional[str] = None


class SelectionIn(BaseModel):
    instruction: str
    selected_filters: list[str] = []
    selected_templates: list[str] = []
    tier: Optional[str] = None
    num_queries: int = 6
    analyst_guidance: Optional[str] = None


class AiMessageIn(BaseModel):
    session_id: str
    role: str       # 'user' | 'assistant' | 'system'
    content: str
    search_id: Optional[int] = None


class FeedRefreshIn(BaseModel):
    otx_api_key: Optional[str] = None


class ClusterIn(BaseModel):
    name: str
    description: str = ""
    actor: str = ""
    mitre_ttps: list[str] = []
    ioc_summary: str = ""
    query_ids: list[int] = []


class AiClusterIn(BaseModel):
    query_ids: list[int]
    provider: Optional[str] = None


class CVEIntelIn(BaseModel):
    """Input for CVE advisory → scoped Shodan detections."""
    advisory: str                      # raw advisory/news text
    scope: Optional[dict] = None       # current scope object from /api/scope
    scope_queries: bool = True         # if True, scope queries to org/CIDRs
    tier: Optional[str] = None         # client-reported tier
    provider: Optional[str] = None


# ---------------------------------------------------------------------------
# Static UI
# ---------------------------------------------------------------------------
# Locate static/ — works whether server.py is in core/ (structured layout)
# or in the project root (flat layout).
_HERE = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = (
    os.path.join(_HERE, "static")                       # flat: ./static
    if os.path.isdir(os.path.join(_HERE, "static"))
    else os.path.join(os.path.dirname(_HERE), "static") # structured: ../static
)
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(path):
        raise HTTPException(404, "UI not installed; static/index.html missing")
    return FileResponse(path)


def _logo_path() -> str:
    for p in [
        os.path.join(os.path.dirname(__file__), "static", "logo.svg"),
        os.path.join(os.path.dirname(__file__), "logo.svg"),
    ]:
        if os.path.exists(p):
            return p
    return ""


@app.get("/logo.svg")
def logo() -> FileResponse:
    p = _logo_path()
    if not p:
        raise HTTPException(404, "logo.svg missing")
    return FileResponse(p, media_type="image/svg+xml")


@app.get("/favicon.ico")
def favicon() -> FileResponse:
    p = _logo_path()
    if not p:
        raise HTTPException(404)
    return FileResponse(p, media_type="image/svg+xml")


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------
def _classify_tier(info: dict) -> dict:
    plan = (info.get("plan") or "").lower()
    unlocked = bool(info.get("unlocked", False))

    if plan in {"enterprise"}:
        tier, label = "enterprise", "Enterprise"
    elif plan in {"corporate", "small-business", "asm"}:
        tier, label = "enterprise", "Corporate"
    elif plan in {"edu", "gov"}:
        tier, label = "enterprise", plan.upper()
    elif plan in {
        "member", "freelancer", "academic", "plus",
        "business", "professional", "enterprise-plus",
    }:
        tier, label = "member", plan.capitalize()
    elif plan in {"oss", "dev", ""}:
        tier, label = "free", "Free"
    else:
        tier, label = ("member" if unlocked else "free"), plan or "unknown"

    usage_limits = info.get("usage_limits", {}) or {}
    qc_limit = usage_limits.get("query_credits", 0)
    qc_remaining = info.get("query_credits", 0)
    qc_used = max(qc_limit - qc_remaining, 0) if qc_limit else None

    sc_limit = usage_limits.get("scan_credits", 0)
    sc_remaining = info.get("scan_credits", 0)
    sc_used = max(sc_limit - sc_remaining, 0) if sc_limit else None

    return {
        "tier": tier,
        "tier_label": label,
        "plan": plan or "unknown",
        "unlocked": unlocked,
        "can_use_paid_filters": unlocked,
        "free_tier_limits": tier == "free",
        "https": bool(info.get("https", False)),
        "telnet": bool(info.get("telnet", False)),
        "usage": {
            "query_credits_used": qc_used,
            "query_credits_remaining": qc_remaining,
            "query_credits_limit": qc_limit or None,
            "scan_credits_used": sc_used,
            "scan_credits_remaining": sc_remaining,
            "scan_credits_limit": sc_limit or None,
        },
    }


# ---------------------------------------------------------------------------
# Meta / health
# ---------------------------------------------------------------------------
@app.get("/api/tier")
def get_tier() -> dict:
    return {"tier": _current_tier}


@app.get("/api/health")
def health() -> dict:
    # BUG-1 FIX: declare global so the assignment persists at module level.
    global _current_tier
    key = db.get_config("shodan_api_key")
    if not key:
        return {
            "status": "needs_api_key",
            "tier": "free",
            "tier_label": "no key",
            "can_use_paid_filters": False,
            "free_tier_limits": True,
            "usage": {},
        }
    try:
        info = _get_engine().api_info()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(503, f"Shodan API not reachable: {e}")
    tier_data = _classify_tier(info)
    _current_tier = tier_data.get("tier", "free")   # ← now actually persists
    return {"status": "ok", **tier_data}


@app.post("/api/config/api-key")
def set_api_key(body: ApiKeyIn) -> dict:
    # BUG-1 FIX: declare global here too.
    global _current_tier
    key = body.api_key.strip()
    if len(key) < 10:
        raise HTTPException(400, "API key looks too short to be valid")
    db.set_config("shodan_api_key", key)
    _reset_engine()
    try:
        info = _get_engine().api_info()
        tier_info = _classify_tier(info)
        _current_tier = tier_info.get("tier", "free")   # ← now actually persists
        audit("api_key_set", {"plan": tier_info["plan"], "tier": tier_info["tier"]})
        return {"status": "ok", **tier_info}
    except Exception as e:
        raise HTTPException(401, f"Key saved but Shodan rejected it: {e}")


@app.delete("/api/config/api-key")
def clear_api_key() -> dict:
    db.delete_config("shodan_api_key")
    _reset_engine()
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Autonomy mode config  (stored in DB so crewai.bat can read it)
# ---------------------------------------------------------------------------
@app.get("/api/config/autonomy")
def get_autonomy() -> dict:
    mode = db.get_config("mcp_autonomy_mode") or "hitl"
    return {"mode": mode}

@app.post("/api/config/autonomy")
def set_autonomy(body: dict = Body(...)) -> dict:
    mode = (body.get("mode") or "hitl").strip().lower()
    if mode not in ("hitl", "scoped", "full"):
        raise HTTPException(400, f"Invalid mode: {mode}. Must be hitl | scoped | full")
    db.set_config("mcp_autonomy_mode", mode)
    audit("autonomy_mode_set", {"mode": mode})
    return {"mode": mode}


# ---------------------------------------------------------------------------
# Filters + templates
# ---------------------------------------------------------------------------
@app.get("/api/filters")
def filters() -> dict:
    return {"filters": FILTER_REFERENCE}


@app.get("/api/templates")
def templates_list() -> dict:
    return {"templates": TEMPLATES}


@app.post("/api/templates/render")
def render(body: TemplateRenderIn) -> dict:
    q = render_template(body.template_id, body.params)
    if q is None:
        raise HTTPException(404, f"Unknown template: {body.template_id}")
    return {"query": q}


# ---------------------------------------------------------------------------
# Query inspection
# ---------------------------------------------------------------------------
PAID_FILTERS = {
    "vuln:": "Shodan CVE matching",
    "has_screenshot:": "screenshot data",
    "has_vuln:": "vulnerability flag",
}


@app.post("/api/inspect-query")
def inspect_query(body: dict = Body(...)) -> dict:
    q = (body.get("query") or "").lower()
    if not q:
        return {"paid_features": [], "can_run": True}
    features = [name for prefix, name in PAID_FILTERS.items() if prefix in q]
    try:
        info = _get_engine().api_info()
        unlocked = bool(info.get("unlocked", False))
    except Exception:
        unlocked = False
    return {
        "paid_features": features,
        "can_run": (not features) or unlocked,
        "unlocked": unlocked,
    }


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------
@app.post("/api/scope")
def set_scope(body: ScopeIn) -> dict:
    global _current_scope
    _current_scope = Scope.from_dict(body.model_dump())
    audit("scope_installed", {"scope": _current_scope.name, "summary": _current_scope.summary()})
    return {"scope": _current_scope.summary()}


@app.get("/api/scope")
def get_scope() -> dict:
    return {
        "name": _current_scope.name,
        "cidrs": _current_scope.cidrs,
        "domains": _current_scope.domains,
        "asns": _current_scope.asns,
        "orgs": _current_scope.orgs,
        "summary": _current_scope.summary(),
        "is_empty": _current_scope.is_empty(),
    }


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------
@app.get("/api/search/progress")
def search_progress_endpoint() -> dict:
    """Lightweight progress poll — called every ~400ms by the UI during a search."""
    return _search_progress


@app.post("/api/search")
async def search(body: SearchIn) -> dict:
    global _last_results, _last_query, _last_search_id, _search_progress

    engine = _get_engine()
    audit("search_start", {"query": body.query, "limit": body.limit, "enrich": body.enrich})

    _search_progress = {"phase": "collecting", "found": 0, "total": body.limit, "query": body.query}

    raw_results, warning = await engine.execute_query(
        body.query, limit=body.limit, tags=body.tags, enrich=body.enrich
    )

    _search_progress = {"phase": "processing", "found": len(raw_results), "total": body.limit, "query": body.query}

    # Respect scope; use override only when the caller explicitly asked for it.
    in_scope, out_of_scope = apply_scope(
        raw_results,
        _current_scope,
        override=body.override_scope,
        override_reason=body.override_reason,
        query=body.query,
    )

    # When scope is active and override not requested, show only in-scope results.
    if body.override_scope or _current_scope.is_empty():
        visible = in_scope + out_of_scope
    else:
        visible = in_scope

    _last_results = visible
    _last_query = body.query

    serialized = [serialize_result(r) for r in visible]
    in_scope_ips = {r.get("ip_str") for r in in_scope}
    for s in serialized:
        s["in_scope"] = s["ip_str"] in in_scope_ips

    _last_search_id = db.search_record(
        body.query, _current_scope.name, serialized, override=body.override_scope
    )

    audit("search_complete", {
        "query": body.query,
        "search_id": _last_search_id,
        "total_returned": len(raw_results),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
    })

    _search_progress = {"phase": "done", "found": len(raw_results), "total": body.limit, "query": body.query}

    return {
        "query": body.query,
        "search_id": _last_search_id,
        "total_returned": len(raw_results),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "results": serialized,
        "warning": warning,
    }


@app.post("/api/bulk")
async def bulk(body: BulkIn) -> dict:
    # BUG-2 FIX: same global declaration required.
    global _last_results, _last_query, _last_search_id

    engine = _get_engine()
    ips = [ip.strip() for ip in body.ips if ip.strip()]
    if not ips:
        raise HTTPException(400, "No IPs provided")

    audit("bulk_start", {"ip_count": len(ips), "enrich": body.enrich})

    raw, warning = await engine.execute_query(
        query="", limit=len(ips), enrich=body.enrich, ip_list=ips
    )
    in_scope, out_of_scope = apply_scope(
        raw,
        _current_scope,
        override=body.override_scope,
        override_reason=body.override_reason,
        query=f"bulk({len(ips)})",
    )

    if body.override_scope or _current_scope.is_empty():
        visible = in_scope + out_of_scope
    else:
        visible = in_scope

    _last_results = visible
    _last_query = f"bulk({len(ips)} IPs)"

    serialized = [serialize_result(r) for r in visible]
    in_scope_ips = {r.get("ip_str") for r in in_scope}
    for s in serialized:
        s["in_scope"] = s["ip_str"] in in_scope_ips

    _last_search_id = db.search_record(
        f"bulk({len(ips)} IPs)",
        _current_scope.name,
        serialized,
        override=body.override_scope,
    )

    return {
        "ip_count": len(ips),
        "in_scope": len(in_scope),
        "out_of_scope": len(out_of_scope),
        "results": serialized,
        "warning": warning,
        "search_id": _last_search_id,
    }


# ---------------------------------------------------------------------------
# Suggestions (propose-approve loop)
# ---------------------------------------------------------------------------
@app.post("/api/suggest")
def suggest(body: SuggestIn) -> dict:
    return {"suggestions": suggest_followups(body.query, _last_results)}


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------
@app.get("/api/saved")
def list_saved() -> dict:
    return {"saved": db.saved_list()}


@app.post("/api/saved")
def add_saved(body: SaveIn) -> dict:
    return db.saved_add(
        uuid.uuid4().hex[:12], body.label.strip(), body.query.strip(), body.watched
    )


@app.delete("/api/saved/{item_id}")
def del_saved(item_id: str) -> dict:
    return {"deleted": db.saved_delete(item_id)}


# ---------------------------------------------------------------------------
# Diff mode
# ---------------------------------------------------------------------------
@app.post("/api/diff")
async def run_diff(body: DiffIn) -> dict:
    global _last_results, _last_query, _last_search_id
    engine = _get_engine()

    raw, warning = await engine.execute_query(body.query, limit=body.limit, enrich=body.enrich)
    in_scope, out_of_scope = apply_scope(
        raw, _current_scope,
        override=body.override_scope,
        override_reason=body.override_reason,
        query=body.query,
    )
    visible = in_scope + (out_of_scope if body.override_scope or _current_scope.is_empty() else [])

    diff_report = diff(body.query, _current_scope.name, visible)

    if body.save_snapshot:
        save_snapshot(body.query, _current_scope.name, visible)
        audit("snapshot_saved", {
            "query": body.query,
            "scope": _current_scope.name,
            "result_count": len(visible),
        })

    _last_results = visible
    _last_query = body.query

    return {
        "query": body.query,
        "result_count": len(visible),
        "diff": diff_report,
        "results": [serialize_result(r) for r in visible],
        "warning": warning,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
@app.get("/api/audit")
def audit_tail_endpoint(limit: int = 50) -> dict:
    return {"events": db.audit_tail(limit)}


# ---------------------------------------------------------------------------
# Search history
# ---------------------------------------------------------------------------
@app.get("/api/history")
def history(limit: int = 50) -> dict:
    return {"history": db.search_history(limit)}


@app.get("/api/history/{search_id}")
def history_load(search_id: int) -> dict:
    global _last_results, _last_query, _last_search_id
    record = db.search_load(search_id)
    if not record:
        raise HTTPException(404, "Search not found")
    _last_results = record.get("results", [])
    _last_query = record.get("query", "")
    _last_search_id = search_id
    return record


@app.delete("/api/history/{search_id}")
def history_delete(search_id: int) -> dict:
    return {"deleted": db.search_delete(search_id)}


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
@app.post("/api/export/csv")
def export_csv() -> Response:
    import csv, io
    _ensure_results()
    if not _last_results:
        raise HTTPException(404, "No results to export. Run a search first.")

    buf = io.StringIO()
    fields = [
        "IP", "Ports", "Port_Count", "Org", "ASN", "Country", "City",
        "Hostnames", "Product", "OS", "Tags", "CVEs", "CVE_Count",
        "CPEs", "Risk_Level", "Risk", "HTTP_Title", "SSL_Subject", "Enriched",
    ]
    w = csv.DictWriter(buf, fieldnames=fields, quoting=csv.QUOTE_ALL)
    w.writeheader()
    for r in _last_results:
        s = serialize_result(r)
        w.writerow({
            "IP": s["ip_str"],
            "Ports": ", ".join(map(str, s["ports"])),
            "Port_Count": s["port_count"],
            "Org": s["org"],
            "ASN": s["asn"],
            "Country": s["country"],
            "City": s["city"],
            "Hostnames": ", ".join(s["hostnames"]),
            "Product": s["product"],
            "OS": s["os"],
            "Tags": ", ".join(s["tags"]),
            "CVEs": ", ".join(s["cves"]),
            "CVE_Count": s["cve_count"],
            "CPEs": ", ".join(s["cpes_internetdb"]),
            "Risk_Level": s["risk_level"],
            "Risk": s["risk_simplified"],
            "HTTP_Title": s["http_title"],
            "SSL_Subject": s["ssl_subject"],
            "Enriched": "Yes" if s["enriched"] else "No",
        })
    audit("export_csv", {"query": _last_query, "rows": len(_last_results)})
    csv_bytes = buf.getvalue().encode("utf-8-sig")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="shodansnipe_{int(datetime.now().timestamp())}.csv"'
            )
        },
    )


@app.post("/api/export/json")
def export_json() -> Response:
    _ensure_results()
    if not _last_results:
        raise HTTPException(404, "No results to export.")
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "query": _last_query,
        "scope": _current_scope.summary(),
        "results": [serialize_result(r) for r in _last_results],
    }
    audit("export_json", {"query": _last_query, "rows": len(_last_results)})
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="shodansnipe_{int(datetime.now().timestamp())}.json"'
            )
        },
    )


# ---------------------------------------------------------------------------
# AI Triage + AI Agent Builder
# ---------------------------------------------------------------------------
import llm


@app.get("/api/llm/settings")
def llm_settings_get() -> dict:
    return llm.get_settings()


@app.post("/api/llm/settings")
def llm_settings_set(body: LLMSettingsIn) -> dict:
    llm.set_settings(
        body.provider, body.model, body.endpoint,
        body.anthropic_key, body.openai_key,
    )
    audit("llm_settings_changed", {"provider": body.provider, "model": body.model})
    return llm.get_settings()


@app.post("/api/llm/goal")
async def llm_goal(body: GoalIn) -> dict:
    effective_tier = body.tier or _current_tier

    # Persist guidance if requested
    if body.save_guidance and body.analyst_guidance:
        db.set_config("analyst_guidance", body.analyst_guidance.strip())

    # Load stored guidance if not provided inline
    guidance = body.analyst_guidance or db.get_config("analyst_guidance") or ""

    if not body.goal.strip():
        raise HTTPException(400, "Goal cannot be empty.")
    try:
        result = await llm.goal_to_query(
            body.goal.strip(),
            body.provider,
            tier=effective_tier,
            num_queries=max(1, min(body.num_queries, 30)),
            analyst_guidance=guidance,
        )
        audit("llm_goal", {
            "goal": body.goal,
            "provider": body.provider or "default",
            "tier": effective_tier,
            "num_queries": body.num_queries,
        })
        return result
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.get("/api/guidance")
def get_guidance() -> dict:
    """Return stored analyst guidance."""
    return {"guidance": db.get_config("analyst_guidance") or ""}


@app.post("/api/guidance")
def set_guidance(body: dict = Body(...)) -> dict:
    """Save analyst guidance for reuse across sessions."""
    text = (body.get("guidance") or "").strip()
    if text:
        db.set_config("analyst_guidance", text)
    else:
        db.delete_config("analyst_guidance")
    return {"saved": bool(text)}


@app.delete("/api/guidance")
def clear_guidance() -> dict:
    db.delete_config("analyst_guidance")
    return {"cleared": True}



@app.post("/api/llm/ask")
async def llm_ask(body: AskIn) -> dict:
    """ASK mode — free-form Q&A about results, syntax, or strategy."""
    if not body.question.strip():
        raise HTTPException(400, "Question cannot be empty.")
    effective_tier = body.tier or _current_tier
    guidance = body.analyst_guidance or db.get_config("analyst_guidance") or ""
    try:
        result = await llm.ask_question(
            question=body.question.strip(),
            current_query=body.query,
            tier=effective_tier,
            analyst_guidance=guidance,
            results_summary=f"{len(_last_results)} results in memory" if _last_results else "no results loaded",
        )
        audit("llm_ask", {"question": body.question[:100], "tier": effective_tier})
        return result
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/selection")
async def llm_selection(body: SelectionIn) -> dict:
    """SELECTION mode — build queries from selected filters and templates."""
    if not body.instruction.strip():
        raise HTTPException(400, "Instruction cannot be empty.")
    effective_tier = body.tier or _current_tier
    guidance = body.analyst_guidance or db.get_config("analyst_guidance") or ""
    try:
        result = await llm.selection_to_queries(
            instruction=body.instruction.strip(),
            selected_filters=body.selected_filters,
            selected_templates=body.selected_templates,
            tier=effective_tier,
            num_queries=max(1, min(body.num_queries, 30)),
            analyst_guidance=guidance,
        )
        audit("llm_selection", {"instruction": body.instruction[:100], "tier": effective_tier})
        return result
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")



async def llm_summarize(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(
            400,
            "No results to summarize. Run a search first (or load a previous search from History).",
        )
    try:
        text = await llm.summarize(
            _last_query,
            [serialize_result(r) for r in _last_results],
            body.provider,
            persona=body.persona or "asm",
        )
        audit("llm_summarize", {
            "query": _last_query,
            "provider": body.provider or "default",
            "results": len(_last_results),
        })
        return {"summary": text}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/rank")
async def llm_rank(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(400, "No results to rank. Run a search first.")
    try:
        ranked = await llm.rank(
            _last_query,
            [serialize_result(r) for r in _last_results],
            body.provider,
        )
        audit("llm_rank", {
            "query": _last_query,
            "provider": body.provider or "default",
            "results": len(_last_results),
        })
        return {"ranked": ranked}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/explain")
async def llm_explain(body: ExplainHostIn) -> dict:
    _ensure_results()
    host = next((r for r in _last_results if r.get("ip_str") == body.ip), None)
    if not host:
        raise HTTPException(404, f"Host {body.ip} not in current result set.")
    try:
        text = await llm.explain_host(serialize_result(host), body.provider)
        audit("llm_explain", {"ip": body.ip, "provider": body.provider or "default"})
        return {"explanation": text}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


@app.post("/api/llm/suggest")
async def llm_suggest(body: TriageIn) -> dict:
    _ensure_results()
    if not _last_results:
        raise HTTPException(400, "No results to base suggestions on. Run a search first.")
    try:
        items = await llm.suggest_queries(
            _last_query,
            [serialize_result(r) for r in _last_results],
            body.provider,
            tier=_current_tier,
        )
        audit("llm_suggest", {
            "query": _last_query,
            "provider": body.provider or "default",
            "suggestions": len(items),
        })
        return {"suggestions": items}
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")


# ---------------------------------------------------------------------------
# AI Conversation History
# ---------------------------------------------------------------------------
@app.post("/api/ai/message")
def ai_message_save(body: AiMessageIn) -> dict:
    msg_id = db.ai_message_add(body.session_id, body.role, body.content, body.search_id)
    return {"id": msg_id}


@app.get("/api/ai/history/{session_id}")
def ai_history_get(session_id: str, limit: int = 200) -> dict:
    messages = db.ai_session_history(session_id, limit=limit)
    return {"session_id": session_id, "messages": messages}


@app.get("/api/ai/sessions")
def ai_sessions() -> dict:
    return {"sessions": db.ai_all_sessions()}


@app.get("/api/ai/latest-session")
def ai_latest_session() -> dict:
    sid = db.ai_latest_session()
    return {"session_id": sid}


@app.delete("/api/ai/session/{session_id}")
def ai_session_delete(session_id: str) -> dict:
    with db._lock:
        db._c().execute("DELETE FROM ai_messages WHERE session_id=?", (session_id,))
        db._c().commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Workspace endpoints (unified — BUG-4 FIX)
#
# The original file had TWO separate workspace sections:
#   /api/workspaces  → called db.workspace_list / db.workspace_save / etc.
#                      which do NOT exist in db.py → AttributeError
#   /api/workspace   → inlined SQL correctly
#
# Resolution: all workspace routes use the inlined SQL pattern via
# _ensure_workspace_schema(). The /api/workspaces routes now work correctly.
# ---------------------------------------------------------------------------

@app.get("/api/workspaces")
def list_workspaces_v2() -> dict:
    """BUG-4 FIX: was calling db.workspace_list() which doesn't exist."""
    _ensure_workspace_schema()
    with db._lock:
        rows = db._c().execute(
            "SELECT id,name,query,search_id,notes,description,session_id,tags,created_at "
            "FROM workspaces ORDER BY created_at DESC"
        ).fetchall()
    return {
        "workspaces": [
            {
                "id": r[0], "name": r[1], "query": r[2], "search_id": r[3],
                "notes": r[4], "description": r[5], "session_id": r[6],
                "tags": r[7], "created_at": r[8],
            }
            for r in rows
        ]
    }


@app.post("/api/workspaces")
def save_workspace_v2(body: WorkspaceSaveIn) -> dict:
    """BUG-4 FIX: was calling db.workspace_save() which doesn't exist."""
    global _last_search_id
    _ensure_workspace_schema()
    sid = _last_search_id
    if not sid and _last_results:
        serialized = [serialize_result(r) for r in _last_results]
        sid = db.search_record(body.query or _last_query, _current_scope.name, serialized, False)
    with db._lock:
        cur = db._c().execute(
            "INSERT INTO workspaces"
            "(name,query,search_id,notes,description,session_id,results_snapshot,panel_layout,tags,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                body.name.strip(),
                body.query or _last_query,
                sid,
                body.notes.strip(),
                body.description,
                body.session_id,
                body.results_snapshot,
                body.panel_layout,
                body.tags,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        db._c().commit()
        ws_id = cur.lastrowid
    audit("workspace_saved", {"id": ws_id, "name": body.name})
    return {"workspace_id": ws_id, "name": body.name}


@app.get("/api/workspaces/{ws_id}")
def load_workspace_v2(ws_id: int) -> dict:
    """BUG-4 FIX: was calling db.workspace_load() which doesn't exist."""
    global _last_results, _last_query, _last_search_id
    _ensure_workspace_schema()
    with db._lock:
        row = db._c().execute(
            "SELECT id,name,query,search_id,notes,description,session_id,"
            "results_snapshot,panel_layout,tags,created_at FROM workspaces WHERE id=?",
            (ws_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Workspace not found")
    ws = {
        "id": row[0], "name": row[1], "query": row[2], "search_id": row[3],
        "notes": row[4], "description": row[5], "session_id": row[6],
        "results_snapshot": row[7], "panel_layout": row[8],
        "tags": row[9], "created_at": row[10],
    }
    # Restore results — try results_snapshot first, then search history
    if ws.get("results_snapshot"):
        try:
            _last_results = json.loads(ws["results_snapshot"])
            _last_query = ws.get("query", "")
            _last_search_id = ws.get("search_id")
        except Exception as e:
            logger.warning("Could not restore results from workspace snapshot: %s", e)
    elif row[3]:
        record = db.search_load(row[3])
        if record:
            _last_results = record.get("results", [])
            _last_query = record.get("query", row[2])
            _last_search_id = row[3]
    audit("workspace_loaded", {"id": ws_id, "name": ws.get("name")})
    return {**ws, "result_count": len(_last_results)}


@app.delete("/api/workspaces/{ws_id}")
def delete_workspace_v2(ws_id: int) -> dict:
    """BUG-4 FIX: was calling db.workspace_delete() which doesn't exist."""
    _ensure_workspace_schema()
    with db._lock:
        db._c().execute("DELETE FROM workspaces WHERE id=?", (ws_id,))
        db._c().commit()
    return {"deleted": True}


# /api/workspace/* (legacy short paths — kept for backward compat with older UI)
@app.post("/api/workspace/save")
def workspace_save_legacy(body: WorkspaceSaveIn) -> dict:
    return save_workspace_v2(body)


@app.get("/api/workspace")
def workspace_list_legacy() -> dict:
    return list_workspaces_v2()


@app.get("/api/workspace/{wid}")
def workspace_load_legacy(wid: int) -> dict:
    return load_workspace_v2(wid)


@app.delete("/api/workspace/{wid}")
def workspace_delete_legacy(wid: int) -> dict:
    return delete_workspace_v2(wid)


@app.post("/api/clear/results")
def clear_results() -> dict:
    global _last_results, _last_query, _last_search_id
    _last_results = []
    _last_query = ""
    _last_search_id = None
    return {"cleared": True}


# ---------------------------------------------------------------------------
# Threat Feed endpoints
# ---------------------------------------------------------------------------
@app.post("/api/feeds/refresh")
async def feeds_refresh(body: FeedRefreshIn = FeedRefreshIn()) -> dict:
    try:
        otx_key = body.otx_api_key or db.get_config("otx_api_key") or None
        result = await threat_feeds.refresh_feeds(otx_api_key=otx_key)
        audit("feeds_refresh", {"total": result["total"], "sources": result["sources"]})
        return result
    except Exception as e:
        raise HTTPException(500, f"Feed refresh failed: {e}")


@app.get("/api/feeds/queries")
def feeds_queries(
    category: str = "",
    source: str = "",
    search: str = "",
    limit: int = 500,
) -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        queries = threat_feeds.get_feed_queries(
            category=category, source=source, search=search, limit=limit
        )
        return {"queries": queries}
    except Exception as e:
        raise HTTPException(500, f"Feed query failed: {e}")


@app.get("/api/feeds/stats")
def feeds_stats() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return threat_feeds.get_feed_stats()
    except Exception as e:
        raise HTTPException(500, f"Feed stats failed: {e}")


@app.get("/api/feeds/categories")
def feeds_categories() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return {"categories": threat_feeds.get_feed_categories()}
    except Exception as e:
        raise HTTPException(500, f"Feed categories failed: {e}")


@app.post("/api/feeds/mark-run/{query_id}")
def feeds_mark_run(query_id: int) -> dict:
    try:
        threat_feeds.mark_query_run(query_id)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/config/otx-key")
def set_otx_key(body: dict = Body(...)) -> dict:
    key = (body.get("key") or "").strip()
    if key:
        db.set_config("otx_api_key", key)
    return {"saved": bool(key)}


# ---------------------------------------------------------------------------
# Cluster endpoints
# ---------------------------------------------------------------------------
@app.post("/api/llm/cve-intel")
async def llm_cve_intel(body: CVEIntelIn) -> dict:
    """
    Read a CVE advisory / news article / NVD entry and generate
    Shodan detection queries scoped to the analyst's environment.
    """
    if not body.advisory.strip():
        raise HTTPException(400, "Advisory text cannot be empty.")
    effective_tier = body.tier or _current_tier
    try:
        result = await llm.cve_intel_to_queries(
            advisory=body.advisory.strip(),
            scope=body.scope,
            scope_queries=body.scope_queries,
            tier=effective_tier,
            provider=body.provider,
        )
        audit("cve_intel", {
            "cve_ids": result.get("cve_ids", []),
            "query_count": len(result.get("queries", [])),
            "tier": effective_tier,
        })
        return result
    except Exception as e:
        raise HTTPException(500, f"CVE Intel analysis failed: {e}")


@app.get("/api/feeds/clusters")
def list_clusters() -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        return {"clusters": threat_feeds.get_clusters()}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/feeds/clusters")
def create_cluster(body: ClusterIn) -> dict:
    try:
        cluster_id = threat_feeds.save_cluster(
            body.name, body.description, body.actor,
            body.mitre_ttps, body.ioc_summary, body.query_ids,
        )
        audit("cluster_created", {"id": cluster_id, "name": body.name})
        return {"cluster_id": cluster_id}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/feeds/clusters/{cluster_id}/queries")
def cluster_queries(cluster_id: int) -> dict:
    try:
        return {"queries": threat_feeds.get_cluster_queries(cluster_id)}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/api/feeds/clusters/{cluster_id}")
def delete_cluster(cluster_id: int) -> dict:
    try:
        threat_feeds.delete_cluster(cluster_id)
        return {"deleted": True}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/feeds/ai-cluster")
async def ai_cluster(body: AiClusterIn) -> dict:
    try:
        threat_feeds._ensure_feed_schema()
        all_q = threat_feeds.get_feed_queries(limit=2000)
        selected = [q for q in all_q if q["id"] in set(body.query_ids)]
        if not selected:
            raise HTTPException(400, "No queries found for given IDs")
        result = await llm.cluster_analysis(selected, body.provider)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"AI cluster analysis failed: {e}")



# ---------------------------------------------------------------------------
# /mcp  —  ShodanSnipe as an MCP SERVER
#
# Exposes ShodanSnipe's capabilities to external agents (Claude Desktop,
# Cursor, Windsurf, custom agents) via JSON-RPC 2.0.
#
# Supports:
#   GET  /mcp          → server info (human-readable)
#   POST /mcp          → JSON-RPC 2.0 dispatcher
#
# Tools exposed:
#   shodan_search      — run a Shodan query, returns results
#   get_results        — return the current in-memory results
#   get_scope          — return the active scope definition
#   set_scope          — set scope from plain text (parsed server-side)
#   get_history        — return recent search history
#   cve_intel          — analyse a CVE advisory and return detection queries
# ---------------------------------------------------------------------------

_MCP_SERVER_INFO = {
    "name": "ShodanSnipe",
    "version": "1.1.0",
    "description": "Attack surface defender console — Shodan search, CVE detection queries, scope-aware results",
}

_MCP_TOOLS = [
    {
        "name": "shodan_search",
        "description": "Run a Shodan query and return matching hosts with ports, CVEs, org, and risk score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search query"},
                "limit": {"type": "integer", "description": "Max results (1-100)", "default": 25},
                "enrich": {"type": "boolean", "description": "Enrich with InternetDB data", "default": False},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_results",
        "description": "Return the current in-memory search results (from the last search run in the console).",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Max results to return", "default": 50},
        }},
    },
    {
        "name": "get_scope",
        "description": "Return the currently active scope definition (org names, CIDRs, ASNs, domains).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "set_scope",
        "description": "Set the active scope from a plain-text description. The server parses CIDRs, ASNs, domains, and org names automatically.",
        "inputSchema": {"type": "object", "properties": {
            "text": {"type": "string", "description": "Free-text scope description, e.g. 'Acme Corp, AS64512, 203.0.113.0/24'"},
        }, "required": ["text"]},
    },
    {
        "name": "get_history",
        "description": "Return recent Shodan search history with result counts.",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "default": 10},
        }},
    },
    {
        "name": "cve_intel",
        "description": "Analyse a CVE advisory or threat intel text and return Shodan detection queries for the affected infrastructure.",
        "inputSchema": {"type": "object", "properties": {
            "advisory": {"type": "string", "description": "CVE advisory, NVD text, vendor bulletin, or threat intel article"},
            "scope_queries": {"type": "boolean", "description": "Scope queries to current org", "default": True},
        }, "required": ["advisory"]},
    },
]


async def _mcp_dispatch(method: str, params: dict, req_id) -> dict:
    """Route a JSON-RPC method to the correct handler."""
    try:
        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": _MCP_SERVER_INFO,
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _MCP_TOOLS}}

        if method == "tools/call":
            tool_name = params.get("name", "")
            args = params.get("arguments", {})
            result_text = await _mcp_call_tool(tool_name, args)
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": result_text}]},
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    except Exception as e:
        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32603, "message": str(e)},
        }


async def _mcp_call_tool(name: str, args: dict) -> str:
    """Execute the named tool and return a text result."""
    # Declare globals at top — Python 3.14 requires global before any use in scope
    global _current_scope
    import json as _json

    if name == "shodan_search":
        engine = _get_engine()
        query = args.get("query", "")
        if not query:
            return "Error: query is required"
        results, warning = await engine.execute_query(
            query, limit=min(args.get("limit", 25), 100), enrich=args.get("enrich", False)
        )
        serialized = [serialize_result(r) for r in results]
        out = {"query": query, "total": len(serialized), "warning": warning, "results": serialized[:50]}
        return _json.dumps(out, default=str)

    if name == "get_results":
        limit = min(args.get("limit", 50), 200)
        serialized = [serialize_result(r) for r in _last_results[:limit]]
        return _json.dumps({"total": len(_last_results), "returned": len(serialized), "results": serialized}, default=str)

    if name == "get_scope":
        return _json.dumps({
            "name": _current_scope.name,
            "cidrs": _current_scope.cidrs,
            "domains": _current_scope.domains,
            "asns": _current_scope.asns,
            "orgs": _current_scope.orgs,
            "is_empty": _current_scope.is_empty(),
        })

    if name == "set_scope":
        text = args.get("text", "").strip()
        if not text:
            return "Error: text is required"
        # Simple parser mirroring the JS parseScope() logic
        import re as _re
        cidrs = _re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', text)
        asns  = [a.replace(" ", "").upper() for a in _re.findall(r'\b(?:AS|asn:)\s*\d+\b', text, _re.I)]
        domains = [d for d in _re.findall(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text, _re.I)
                   if not _re.match(r'^\d+\.\d+\.\d+\.\d+$', d)]
        stripped = _re.sub(r'\b(?:AS|asn:)\s*\d+\b', '', text, flags=_re.I)
        stripped = _re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', '', stripped)
        stripped = _re.sub(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', '', stripped, flags=_re.I)
        stripped = _re.sub(r'(?:org|cidr|domain|asn|scope|name)\s*[:=]', '', stripped, flags=_re.I)
        stripped = _re.sub(r'\band\b|\bor\b|[,;|]', ' ', stripped, flags=_re.I)
        orgs = [s.strip() for s in stripped.split() if len(s.strip()) > 2 and not s.strip().isdigit()]
        _current_scope = Scope(
            name=orgs[0] if orgs else (domains[0] if domains else (cidrs[0] if cidrs else "mcp-scope")),
            cidrs=cidrs, domains=domains, asns=asns, orgs=orgs,
        )
        audit("mcp_set_scope", {"text": text[:200]})
        return _json.dumps({"set": True, "scope": _current_scope.summary()})

    if name == "get_history":
        limit = min(args.get("limit", 10), 50)
        history = db.search_history(limit=limit)
        return _json.dumps({"history": history}, default=str)

    if name == "cve_intel":
        advisory = args.get("advisory", "")
        if not advisory:
            return "Error: advisory is required"
        scope_data = {
            "name": _current_scope.name, "cidrs": _current_scope.cidrs,
            "domains": _current_scope.domains, "asns": _current_scope.asns,
            "orgs": _current_scope.orgs, "is_empty": _current_scope.is_empty(),
        }
        result = await llm.cve_intel_to_queries(
            advisory=advisory, scope=scope_data,
            scope_queries=args.get("scope_queries", True), tier=_current_tier,
        )
        audit("mcp_cve_intel", {"cve_ids": result.get("cve_ids", [])})
        return _json.dumps(result, default=str)

    return f"Error: unknown tool '{name}'"


@app.get("/mcp")
def mcp_info() -> dict:
    """Human-readable MCP server info."""
    return {
        "server": _MCP_SERVER_INFO,
        "protocol": "JSON-RPC 2.0",
        "usage": "POST /mcp with Content-Type: application/json",
        "tools": [{"name": t["name"], "description": t["description"]} for t in _MCP_TOOLS],
        "example": {
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "shodan_search", "arguments": {"query": "org:\"Acme Corp\" port:443", "limit": 10}},
        },
    }


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> JSONResponse:
    """MCP JSON-RPC 2.0 endpoint — ShodanSnipe as an agent tool server."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")

    response = await _mcp_dispatch(method, params, req_id)
    return JSONResponse(response)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000) 
