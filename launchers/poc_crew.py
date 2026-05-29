#!/usr/bin/env python3
"""
poc_crew.py — ShodanSnipe + CrewAI Dynamic Threat-Hunting Crew
===============================================================

Three-agent hierarchical crew:
  MANAGER    — validates scope, enforces order, deduplicates findings
  RESEARCHER — dynamically generates search plan from scope characteristics,
               runs searches, dedups results, pivots from live data
  ANALYST    — dynamic TTP mapping and threat intel from actual results

AUTONOMY MODE (set MCP_AUTONOMY_MODE env var or via crewai.bat):
  hitl    — Human-in-the-Loop: crew pauses and asks before each action
  scoped  — Runs freely within defined scope, no per-action prompts
  full    — Full autonomous, no confirmation (audit log always on)

USAGE:
  crewai.bat anthropic          ← reads scope + mode from UI
  crewai.bat anthropic scoped   ← override mode
"""

import os
import sys
import json
import socket

# ── Make every folder importable (single source of truth: _bootstrap.py) ────
# This file may live in launchers/ (structured) or the root (flat). Find the
# project root, add it to the path, then import the bootstrap which wires up
# core/, tools/, agents/.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (_HERE, os.path.dirname(_HERE)):
    if os.path.isfile(os.path.join(_candidate, "_bootstrap.py")):
        sys.path.insert(0, _candidate)
        break
import _bootstrap  # noqa: F401  — adds core/tools/agents to sys.path

# ── Dependency check ───────────────────────────────────────────────────────
def _check_deps():
    missing = []
    try: import crewai
    except ImportError: missing.append("crewai")
    try: import requests
    except ImportError: missing.append("requests")
    if missing:
        print("Missing packages. Install with:")
        print(f"  pip install {' '.join(missing)}")
        sys.exit(1)

_check_deps()

import requests
from crewai import Agent, Crew, Process, Task, LLM
from shodansnipe_tools import (
    ShodanSearchTool, GetResultsTool, SetScopeTool,
    GetScopeTool, CVEIntelTool, GetHistoryTool,
    _check_server, SHODANSNIPE_URL,
)

# NMAP recon agent (optional — only loads if nmap tooling is present)
try:
    from nmap_recon_agent import build_nmap_agent, build_nmap_tasks
    _NMAP_AGENT_AVAILABLE = True
except ImportError:
    _NMAP_AGENT_AVAILABLE = False

# Toggle the NMAP stage via env var (default on if available).
# Set ENABLE_NMAP=0 to skip active scanning and stay passive (Shodan only).
ENABLE_NMAP = os.getenv("ENABLE_NMAP", "1") == "1" and _NMAP_AGENT_AVAILABLE

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

TARGET_ORG    = os.getenv("TARGET_ORG", "")
TARGET_SCOPE  = os.getenv("TARGET_SCOPE", "")
MCP_AUTONOMY  = os.getenv("MCP_AUTONOMY_MODE", "hitl").lower()
CVE_ADVISORY  = os.getenv("CVE_ADVISORY", "")
LLM_PROVIDER  = os.getenv("LLM_PROVIDER", "openai")


# ═══════════════════════════════════════════════════════════════════════════
#  CREDIT-AWARE LIMIT
# ═══════════════════════════════════════════════════════════════════════════

def _get_search_limit() -> int:
    """
    Return a search result limit based on available Shodan query credits.
    - >80% credits remaining  → 200 results
    - 50-80% remaining        → 100 results
    - 20-50% remaining        → 50 results
    - <20% remaining          → 25 results (conservative)
    - Unknown/free tier       → 100 results (reasonable default)
    """
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/health", timeout=5)
        if not r.ok:
            return 100
        d = r.json()
        usage = d.get("usage", {}) or {}
        remaining = usage.get("query_credits_remaining")
        limit_val  = usage.get("query_credits_limit")

        if remaining is None or limit_val is None or limit_val == 0:
            # Free tier or unknown — use 100
            return 100

        pct = remaining / limit_val
        if pct > 0.80:
            lim = 200
        elif pct > 0.50:
            lim = 100
        elif pct > 0.20:
            lim = 50
        else:
            lim = 25

        print(f"  [Credits] {remaining}/{limit_val} ({pct*100:.0f}%) → limit={lim}")
        return lim

    except Exception:
        return 100


# ═══════════════════════════════════════════════════════════════════════════
#  SCOPE RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════

def resolve_scope():
    """Return (target_org, target_scope, scope_parts).
    Priority: env vars (from bat) > server API > interactive prompt.
    """
    global TARGET_ORG, TARGET_SCOPE

    # 1. Env vars set by crewai.bat reading /api/scope
    if TARGET_ORG.strip():
        scope = TARGET_SCOPE or TARGET_ORG
        print(f"  Scope from UI settings: {scope}")
        return TARGET_ORG, scope

    # 2. Fetch live from the running ShodanSnipe server
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/scope", timeout=5)
        if r.ok:
            d = r.json()
            if not d.get("is_empty"):
                orgs      = d.get("orgs", [])
                cidrs     = d.get("cidrs", [])
                asns      = d.get("asns", [])
                domains   = d.get("domains", [])
                extra_q   = (d.get("extra_query") or "").strip()
                name      = d.get("name", "")
                parts = []
                if orgs:    parts.extend([f'org:"{o}"' for o in orgs])
                if cidrs:   parts.extend([f"net:{c}" for c in cidrs])
                if asns:    parts.extend(asns)
                if domains: parts.extend([f"hostname:{dom}" for dom in domains])
                if extra_q: parts.append(extra_q)
                TARGET_ORG   = orgs[0] if orgs else (name or (domains[0] if domains else extra_q[:30] if extra_q else ""))
                TARGET_SCOPE = " ".join(parts) if parts else name
                print(f"  Scope from server: {TARGET_SCOPE or name}")
                if extra_q:
                    print(f"  Free-form query:   {extra_q}")
                return TARGET_ORG, TARGET_SCOPE or name
    except Exception as e:
        print(f"  (Could not reach server for scope: {e})")

    # 3. Interactive prompt
    print("\n" + "="*60)
    print("  MANAGER: No target defined in UI or server.")
    print("  What is the scope of this scan?")
    print("="*60)
    print("  Examples:")
    print('    org:"SANS Institute"')
    print("    net:203.0.113.0/24, hostname:sans.org")
    print("    SANS, sans.org, AS14618")
    print()
    scope_input = input("  Enter target scope: ").strip()

    if not scope_input:
        print("\nNo scope provided. Cannot proceed.")
        sys.exit(1)

    # Parse: extract CIDRs, ASNs, domains, rest is org
    import re as _re
    cidrs_found   = _re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b', scope_input)
    asns_found    = _re.findall(r'\bAS\d+\b', scope_input, _re.I)
    domains_found = [x for x in _re.findall(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', scope_input, _re.I)
                     if not _re.match(r'\d+\.\d+\.\d+\.\d+', x)]

    # Attempt hostname resolution for verbatim scope enrichment
    for dom in domains_found[:3]:
        try:
            ip = socket.gethostbyname(dom)
            print(f"  Resolved {dom} → {ip}")
        except Exception:
            pass

    TARGET_SCOPE = scope_input
    TARGET_ORG   = scope_input.split(",")[0].strip().strip('"\'')
    print(f"\n  Scope: {TARGET_SCOPE}")
    print(f"  Org:   {TARGET_ORG}")
    print()
    return TARGET_ORG, TARGET_SCOPE


# ═══════════════════════════════════════════════════════════════════════════
#  PREFLIGHT
# ═══════════════════════════════════════════════════════════════════════════

def preflight():
    print("\n" + "="*60)
    print("  ShodanSnipe + CrewAI — Dynamic Threat-Hunting Crew")
    print(f"  LLM provider: {LLM_PROVIDER}")
    print(f"  Autonomy mode: {MCP_AUTONOMY.upper()}")
    if TARGET_ORG:
        print(f"  Target org:    {TARGET_ORG}")
    if TARGET_SCOPE:
        print(f"  Scope query:   {TARGET_SCOPE}")
    print("="*60)

    if MCP_AUTONOMY == "full":
        print("\n  ⚠  WARNING: FULL AUTONOMOUS mode — no confirmations.")
        confirm = input("\n  Proceed? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("  Aborted.")
            sys.exit(0)

    if not _check_server():
        print(f"\n  [ERROR] Cannot reach ShodanSnipe at {SHODANSNIPE_URL}")
        print("  Start the server: python server.py")
        sys.exit(1)

    print(f"\n  ShodanSnipe: READY at {SHODANSNIPE_URL}")


# ═══════════════════════════════════════════════════════════════════════════
#  HITL CONFIRMATION WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

def confirm_action(description: str, details: str = "") -> bool:
    """Ask human to approve an action. Returns True if approved."""
    if MCP_AUTONOMY in ("full", "scoped"):
        print(f"  [AUTO] Executing: {description}")
        return True
    # HITL: ask
    print(f"\n  ─── CONFIRMATION REQUIRED (HITL mode) ───")
    print(f"  Action: {description}")
    if details:
        print(f"  Details: {details}")
    choice = input("  Approve? (y/n): ").strip().lower()
    return choice == "y"


# ═══════════════════════════════════════════════════════════════════════════
#  DYNAMIC SEARCH PLAN BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_search_plan(target_org: str, target_scope: str, limit: int) -> str:
    """
    Build a rich, dynamic search plan for the Researcher task.
    Generates many search combinations across ports, products, TLS, services etc.
    Scopes each search correctly using whatever scope terms are available.
    """
    import re as _re

    # Parse scope into components
    orgs    = _re.findall(r'org:"([^"]+)"', target_scope)
    cidrs   = _re.findall(r'net:(\S+)', target_scope)
    asns    = _re.findall(r'\bAS\d+\b', target_scope, _re.I)
    hosts   = _re.findall(r'hostname:(\S+)', target_scope)

    # Build scoping atoms — we'll combine these with search terms
    scope_atoms = []
    for o in orgs:    scope_atoms.append(f'org:"{o}"')
    for c in cidrs:   scope_atoms.append(f'net:{c}')
    for a in asns:    scope_atoms.append(a)
    for h in hosts:   scope_atoms.append(f'hostname:{h}')
    if not scope_atoms:
        scope_atoms = [f'org:"{target_org}"']

    # Use the first atom as the primary scope term (most selective)
    primary = scope_atoms[0]
    full    = target_scope if target_scope else primary

    # ── SEARCH CATALOGUE ──────────────────────────────────────────────────
    # Each entry: (query, description, why_it_matters)
    searches = [
        # Surface scan — full scope
        (full,
         "Full scope surface scan",
         "Establishes baseline — what's exposed across all scope terms"),

        # All scope atoms separately (catches assets under different terms)
        *[(atom, f"Scope atom: {atom}", "Isolates assets under this specific filter")
          for atom in scope_atoms[1:3]],  # up to 2 extra atoms

        # Remote access
        (f"{primary} port:22,3389,5900,23,21",
         "Remote access services",
         "SSH/RDP/VNC/Telnet/FTP — high-value lateral movement targets"),

        # Web services
        (f"{primary} port:80,443,8080,8443,8000,8888",
         "Web services",
         "HTTP/HTTPS — phishing, credential harvesting, web vulns"),

        # Database exposure
        (f"{primary} port:3306,5432,1433,27017,6379,9200,5984",
         "Database services",
         "MySQL/Postgres/MSSQL/MongoDB/Redis/Elastic — data exfil risk"),

        # Expired/self-signed certs
        (f"{primary} ssl.cert.expired:true",
         "Expired SSL certificates",
         "Expired certs = maintenance gaps, possible forgotten assets"),

        # HTTP title hunting
        (f"{primary} http.title:\"login\"",
         "Login pages",
         "Public login pages — credential stuffing, brute force targets"),

        (f"{primary} http.title:\"admin\"",
         "Admin interfaces",
         "Exposed admin panels — direct access risk"),

        (f"{primary} http.title:\"dashboard\"",
         "Dashboards",
         "Monitoring/BI dashboards — data exposure"),

        # Specific high-value products
        (f"{primary} product:\"Apache httpd\"",
         "Apache HTTP servers",
         "Check version for known CVEs (e.g. Log4Shell era, mod_rewrite)"),

        (f"{primary} product:\"nginx\"",
         "Nginx servers",
         "Version fingerprinting for known vulns"),

        (f"{primary} product:\"OpenSSH\"",
         "SSH servers",
         "Version-specific vulnerabilities, brute force surface"),

        # Cloud/DevOps exposure
        (f"{primary} port:2375,2376,4243",
         "Docker API",
         "Unauthenticated Docker daemon — full host compromise"),

        (f"{primary} port:6443,8443 product:\"Kubernetes\"",
         "Kubernetes API",
         "K8s API exposure — cluster takeover risk"),

        # Network devices
        (f"{primary} port:161,162",
         "SNMP",
         "SNMP v1/v2c = community string brute force, network topology leak"),

        (f"{primary} port:23",
         "Telnet",
         "Cleartext protocol — credential interception"),
    ]

    # ── FORMAT AS TASK INSTRUCTIONS ───────────────────────────────────────
    plan_lines = [
        f"Run a comprehensive Shodan reconnaissance of {target_org}.",
        f"Full scope: {target_scope}",
        f"Result limit per search: {limit}",
        "",
        "SEARCH PLAN — execute in order, read results after each, STOP if you find",
        "something critical and pivot to investigate it deeper before continuing:",
        "",
    ]

    for i, (q, label, reason) in enumerate(searches, 1):
        plan_lines.append(f"  Search {i:02d}: {q}")
        plan_lines.append(f"           [{label}] — {reason}")
        plan_lines.append("")

    plan_lines += [
        "DEDUPLICATION RULE:",
        "  If you see the same IP in multiple searches, count it ONCE.",
        "  Merge its ports and CVEs into a single finding.",
        "  Report total unique IPs found, not total search hits.",
        "",
        "PIVOT RULE:",
        "  After each search, ask: what does this result suggest I look for next?",
        "  If you find an unexpected ASN → run: asn:AS<number>",
        "  If you find a product with a version → check that version for known CVEs",
        "  If you find SSL subjects → extract the CN domain and search hostname:<domain>",
        "  If you find an IP range pattern → add net:<cidr> search",
        "",
        "DYNAMIC PIVOT QUERIES:",
        "  Based on what you ACTUALLY find, generate 3-5 new Shodan queries",
        "  that no template could have predicted. These must reference specific",
        "  data from the results (exact version strings, cert subjects, ASNs, etc.).",
        "",
        "Use correct Shodan syntax: no OR/AND/NOT, no wildcards.",
        "Each search: note result count, top 3 IPs, any CVEs, risk verdict.",
    ]

    return "\n".join(plan_lines)


# ═══════════════════════════════════════════════════════════════════════════
#  LLM SETUP
# ═══════════════════════════════════════════════════════════════════════════

def build_llm() -> LLM:
    if LLM_PROVIDER == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            print("Set ANTHROPIC_API_KEY env var to use Anthropic Claude.")
            sys.exit(1)
        return LLM(model="claude-sonnet-4-6", api_key=key, provider="anthropic")
    elif LLM_PROVIDER == "ollama":
        return LLM(
            model="openai/llama3.2",
            base_url=os.getenv("OLLAMA_URL", "http://localhost:11434/v1"),
            api_key="ollama", provider="litellm",
        )
    else:
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            print("Set OPENAI_API_KEY env var.")
            sys.exit(1)
        return LLM(model="gpt-4o-mini", api_key=key)


# ═══════════════════════════════════════════════════════════════════════════
#  CREW BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_crew(llm: LLM, target_org: str, target_scope: str, search_limit: int):

    search  = ShodanSearchTool()
    results = GetResultsTool()
    scope   = SetScopeTool()
    scope_r = GetScopeTool()
    cve     = CVEIntelTool()
    history = GetHistoryTool()

    # ── MANAGER ─────────────────────────────────────────────────────────────
    manager_agent = Agent(
        role="Crew Manager and Scope Enforcer",
        goal=(
            f"Keep the crew on scope and in order for target: {target_org or 'UNDEFINED'}. "
            "Validate scope, deduplicate findings across all searches, "
            "and produce the final prioritised report."
        ),
        backstory=(
            "You are a senior security operations manager. "
            "You confirm scope before anything runs. "
            "You enforce that the Researcher deduplicates — if the same IP appears "
            "in multiple searches, it counts once with merged ports and CVEs. "
            "You never let the crew report inflated numbers from duplicates. "
            "You enforce run order: Researcher → Analyst → your final report."
        ),
        tools=[scope, scope_r, history],
        llm=llm, verbose=True, allow_delegation=True, max_iter=5,
    )

    # ── RESEARCHER ──────────────────────────────────────────────────────────
    researcher_agent = Agent(
        role="Creative Attack Surface Researcher",
        goal=(
            f"Execute the full search plan for {target_org}, "
            f"deduplicate results across all {len(build_search_plan(target_org,target_scope,search_limit).splitlines())} searches, "
            "and identify pivot opportunities from what was ACTUALLY found."
        ),
        backstory=(
            "You are a red team operator specialising in Shodan reconnaissance. "
            "You run every search in the plan, then merge results by IP address — "
            "if 192.168.1.1 appears in search 1 and search 5, you report it ONCE "
            "with all its ports and CVEs combined. "
            "You pivot based on what you see: version strings, cert subjects, ASN patterns. "
            "You never use OR/AND/NOT operators. No wildcards. "
            f"Each search uses limit={search_limit}."
        ),
        tools=[search, results, scope_r],
        llm=llm, verbose=True, allow_delegation=False, max_iter=20,
    )

    # ── ANALYST ─────────────────────────────────────────────────────────────
    analyst_agent = Agent(
        role="Dynamic Threat Intelligence Analyst",
        goal=(
            "Produce threat intelligence from the DEDUPLICATED result set. "
            "Map to specific MITRE ATT&CK TTPs. Write prose, not templates."
        ),
        backstory=(
            "You are a threat intelligence analyst with 12 years experience. "
            "You read the actual deduplicated results before drawing conclusions. "
            "You cite technique IDs (T1133, T1190 etc) mapped to specific findings. "
            "You identify threat actor patterns where evidence supports it. "
            "You write 3-4 paragraphs of analyst prose with a risk verdict. "
            "You never pad with filler."
        ),
        tools=[results, cve, history],
        llm=llm, verbose=True, allow_delegation=False, max_iter=6,
    )

    # ── TASK 0: Validate scope ───────────────────────────────────────────────
    task_validate = Task(
        description=(
            "1. Call get_scope to verify scope is defined.\n"
            "2. If empty, output: 'MANAGER: Scope undefined — cannot proceed.' and stop.\n"
            f"3. If set, confirm: 'MANAGER: Scope confirmed — {target_scope}'\n"
            f"4. Call set_scope with: '{target_scope or target_org}'\n"
            f"5. List the top 5 asset categories most likely exposed for {target_org}."
        ),
        expected_output="Scope confirmation and prioritised asset category list.",
        agent=manager_agent,
    )

    # ── TASK 1: Comprehensive recon with dynamic search plan ─────────────────
    search_plan = build_search_plan(target_org, target_scope, search_limit)

    task_recon = Task(
        description=search_plan,
        expected_output=(
            f"Deduplicated findings: total unique IPs (not search hits). "
            "For each unique host: IP, merged ports, merged CVEs, risk level, "
            "which searches found it. "
            "3-5 dynamic pivot queries derived from actual findings. "
            "Top 5 most critical findings overall."
        ),
        agent=researcher_agent,
        context=[task_validate],
    )

    # ── TASK 2: Dynamic intelligence ─────────────────────────────────────────
    task_intel = Task(
        description=(
            "Call get_current_results to read the DEDUPLICATED findings.\n\n"
            "Write a threat intelligence assessment. NOT a template. Read the data first.\n\n"
            "Cover:\n"
            "1. What the deduplicated exposure profile means for this org's security posture\n"
            "2. Specific MITRE ATT&CK TTPs mapped to actual findings (T-numbers, specific)\n"
            "3. Threat actor targeting assessment — random exposure or targeted pattern?\n"
            "4. Risk verdict: CRITICAL / HIGH / MEDIUM / LOW with justification\n"
            "5. Single most urgent remediation action\n\n"
            + (f"Also analyse this CVE advisory:\n{CVE_ADVISORY}\n\n" if CVE_ADVISORY else "")
            + "Write 3-4 paragraphs of prose. No bullet lists. No filler."
        ),
        expected_output=(
            "3-4 paragraphs of analyst prose. Risk verdict with justification. "
            "MITRE TTP citations. Most urgent action."
            + (" CVE verdict: EXPOSED / POSSIBLY EXPOSED / NOT DETECTED." if CVE_ADVISORY else "")
        ),
        agent=analyst_agent,
        context=[task_recon],
    )

    # ── TASK 3: Final report ─────────────────────────────────────────────────
    task_report = Task(
        description=(
            "Produce the final threat exposure report. Use these exact headings:\n\n"
            "## Executive Summary\n"
            "2-3 sentences. Plain language. What was found, risk level, urgency.\n\n"
            "## Unique Hosts Found\n"
            "Total deduplicated IP count. Break down by risk level.\n\n"
            "## Critical Findings\n"
            "Up to 5, highest risk first. Asset, exposure, risk, why it matters.\n\n"
            "## Threat Intelligence\n"
            "Analyst assessment (summarise or paste).\n\n"
            "## Pivot Opportunities\n"
            "3-5 dynamic queries from the Researcher with one-sentence rationale each.\n\n"
            "## Network Recon Hand-off (if NMAP stage ran)\n"
            "The prioritised list of hosts for the senior network operator: which "
            "hosts are HIGH priority for intensive testing and why. Skip this section "
            "if no active scan was performed.\n\n"
            "## Recommended Actions\n"
            "4-6 specific, actionable items. Owner + timeline for each.\n\n"
            "## Monitoring Queries\n"
            "3-5 validated Shodan queries for ongoing detection.\n\n"
            "Target: under 800 words total."
        ),
        expected_output=(
            "Complete report with all 7 sections. "
            "Unique host count (deduplicated). "
            "All Shodan queries valid syntax."
        ),
        agent=manager_agent,
        context=[task_validate, task_recon, task_intel],
    )

    # ── Optional NMAP recon stage ────────────────────────────────────────
    # Inserts an active-scan + triage step between Shodan recon and analysis.
    # Produces a prioritised hand-off for the senior network operator.
    agents = [manager_agent, researcher_agent, analyst_agent]
    tasks  = [task_validate, task_recon]

    if ENABLE_NMAP:
        nmap_agent = build_nmap_agent(llm)
        nmap_tasks = build_nmap_tasks(nmap_agent, prior_task=task_recon)
        agents.insert(2, nmap_agent)          # after researcher, before analyst
        tasks.extend(nmap_tasks)
        # Let the analyst and final report see the NMAP triage output
        task_intel.context = list(task_intel.context or []) + [nmap_tasks[-1]]
        task_report.context = list(task_report.context or []) + [nmap_tasks[-1]]
        print("  [NMAP] Active recon stage ENABLED — stealthy scan + triage")
    else:
        print("  [NMAP] Active recon stage disabled (passive Shodan only)")

    tasks.extend([task_intel, task_report])

    return Crew(
        agents=agents,
        tasks=tasks,
        process=Process.sequential,
        verbose=True,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    preflight()
    target_org, target_scope = resolve_scope()
    search_limit = _get_search_limit()

    llm  = build_llm()
    crew = build_crew(llm, target_org, target_scope, search_limit)

    print(f"\n  Target:       {target_org}")
    print(f"  Scope:        {target_scope}")
    print(f"  Mode:         {MCP_AUTONOMY.upper()}")
    print(f"  Search limit: {search_limit} results/query")
    print("\nStarting crew...\n")
    print("="*60)

    try:
        result = crew.kickoff()
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Crew failed: {e}")
        raise

    print("\n" + "="*60)
    print("  FINAL THREAT EXPOSURE REPORT")
    print("="*60)
    print(result)

    out_path = f"report_{target_org.replace(' ','_').lower()}.md"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# ShodanSnipe Threat Report — {target_org}\n\n")
            f.write(str(result))
        print(f"\nReport saved to: {out_path}")
    except Exception as e:
        print(f"(Could not save report: {e})")


if __name__ == "__main__":
    main()
