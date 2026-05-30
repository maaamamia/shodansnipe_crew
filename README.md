# ShodanSnipe AI (SANS598)
**An agentic attack-surface-management console.** A CrewAI team plans Shodan
searches from your scope, confirms what's live with stealthy Nmap scans,
triages hosts ,cross-references amd creates searches based on CVEs, and writes an
executive threat report — with human-in-the-loop controls. Full autonomouse is still under development and will he used for global intelligence queued for next version.

This tool is still under active develoment so dont foeget to watch this project.
```
You set a scope  →  A team of AI agents works it  →  A prioritised threat report
org:"Acme Corp"      Recon → Nmap → Vuln → Report     + a hand-off list of the
hostname:acme.com    (Manager orchestrates)           hosts a human should test
net:203.0.113.0/24                                     intensively
```

---

## Table of contents

- [Quick start](#quick-start)
- [Project structure](#project-structure)
- [The agent team](#the-agent-team)
- [The web console](#the-web-console)
- [Scope configuration](#scope-configuration)
- [The Nmap recon stage](#the-nmap-recon-stage)
- [Autonomy modes](#autonomy-modes)
- [MCP server](#mcp-server)
- [Environment variables](#environment-variables)
- [Extending the system](#extending-the-system)
- [Troubleshooting](#troubleshooting)

---

## Quick start

### Prerequisites

| Need | Version / note |
|------|----------------|
| Python | **3.12** (CrewAI wheel compatibility — not 3.11 or 3.13) |
| Shodan API key | free key works; paid unlocks `vuln:` and higher limits |
| LLM key | Anthropic, OpenAI, **or** local Ollama (no key) |
| nmap | only for the active-recon stage — `choco/apt/brew install nmap` |

### Install

```bash
pip install -r requirements.txt
```

### Run (two terminals)

```bash
# Terminal 1 — start the server
cd core
python server.py            # prompts for a DB passphrase on first run

# Terminal 2 — run the crew
cd launchers
setup_crewai.bat            # one-time: venv + deps + nmap check (Windows)
crewai.bat anthropic        # reads scope + autonomy mode from the UI
```

Open the console at **http://127.0.0.1:8000**.

> Open the console at the exact URL the server prints. Opening `index.html` as a
> file, or from a different dev server, will break the API calls.

---

## Project structure

```
shodansnipe/
│
├── _bootstrap.py      Import-path setup — every launcher imports this first
├── requirements.txt   pip dependencies
├── README.md          This file
├── STRUCTURE.md       The folder layout in detail
├── DEPENDENCIES.md    Module interaction map + required local core modules
│
├── core/              The engine (rarely changes)
│   ├── server.py            FastAPI: REST API + MCP server + DB + serves the UI
│   ├── shodansnipe_core.py  Shodan query execution, rate limiting, risk scoring
│   ├── llm.py               LLM client: goal→query, CVE intel, summarise
│   └── threat_feeds.py      C2 tracker / STIX-TAXII feed crawler
│
├── agents/            One file per team member (see The Agent Team)
│   ├── recon_agent.py       Attack Surface Reconnaissance Specialist
│   ├── nmap_recon_agent.py  Stealthy Network Reconnaissance Specialist
│   ├── vuln_agent.py        Vulnerability Intelligence Analyst
│   ├── report_agent.py      Security Report Writer
│   ├── example_crew.py      Assembles the team into a simple crew
│   └── example_crew_mcp.py  Same, via the MCP adapter (auto tool discovery)
│
├── tools/             CrewAI tool wrappers (the agents' capabilities)
│   ├── shodansnipe_tools.py search, results, scope, CVE, history
│   └── nmap_tool.py         NmapDiscoveryTool, NmapTriageTool
│
├── skills/            How to extend the system
│   ├── BUILDING_AGENTS.md
│   └── BUILDING_TOOLS.md
│
├── launchers/         Entry points you run
│   ├── poc_crew.py          The production orchestrator (full pipeline)
│   ├── run_server.bat       Start the server (run first)
│   ├── crewai.bat           Run the crew (reads scope + mode from server)
│   └── setup_crewai.bat     One-time venv + deps + nmap check
│
├── static/
│   └── index.html           The single-file web console
│
└── docs/
    ├── TEAM.md              Visual roster of every agent
    ├── CREWAI_SETUP.md      Step-by-step crew setup + env vars
    └── sec598_submission.md SEC598 coin submission writeup
```

The key architectural point: **the crew does not import the server.** They are
separate processes that talk over HTTP (REST + the `/mcp` endpoint). That's why
you start the server first, then run the crew.

---

## The agent team

A pipeline of specialists, each handing off to the next. The Manager
orchestrates; a human specialist sits in the middle for intensive testing.

```
MANAGER ──────────────── validates scope, enforces order, dedups, final report
   │
   ├─ RECON SPECIALIST ──── passive recon: maps the attack surface (Shodan)
   │
   ├─ NMAP RECON ────────── active recon: confirm live
   |                        stealthy if confirmed active defenses 
   |                        intense scan if no protections detected. 
   │               
   │
   ├─ VULN ANALYST ──────── CVE cross-reference, detection queries, severity
   │
   └─ REPORT WRITER ─────── synthesises everything into the executive report
```

| Agent | File | Tools | Output |
|-------|------|-------|--------|
| **Recon Specialist** | `recon_agent.py` | shodan_search, set_scope, get_scope | in-scope live hosts + risk |
| **Nmap Recon** | `nmap_recon_agent.py` | nmap_discovery_scan, nmap_triage | HIGH/MED/LOW hand-off list |
| **Vuln Analyst** | `vuln_agent.py` | cve_intel, shodan_search, get_results | CVE detection queries + verdict |
| **Report Writer** | `report_agent.py` | get_results, get_history | executive threat report |

Every agent is a standalone module exporting `build_<name>_agent(llm)` and
`build_<name>_tasks(...)`. They are reusable, individually testable, and
individually runnable. See `docs/TEAM.md` for full roster cards.

The production orchestrator (`launchers/poc_crew.py`) additionally runs a
Manager and a dynamic Researcher with a 14-16 search credit-aware plan; the
`agents/example_crew.py` is a minimal reference that assembles Recon → Vuln →
Report.

### Run one agent in isolation

```python
from recon_agent import build_recon_agent, build_recon_tasks
from crewai import Crew, Process, LLM
llm = LLM(model="gpt-4o-mini")
agent = build_recon_agent(llm)
tasks = build_recon_tasks(agent, "Acme Corp", 'org:"Acme Corp"')
Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=True).kickoff()
```

---

## The web console

Served by `core/server.py` at http://127.0.0.1:8000.

| Panel | What it does |
|-------|--------------|
| **AI Analyst** | Describe a goal in plain English; the AI builds a queue of scoped Shodan queries you approve before running. Has a persistent Guidance field and an inline scope-setter. |
| **Query Builder** | Direct Shodan input with a filter library, templates, a live syntax validator, and diff mode. Picking a filter maps it to the active scope. |
| **Results** | SOURCE selector (Current / All History / By Scope) + a filter bar: Risk, Scope, Port, Org, Country, Product, CVE, ASN. Sort, column picker, CSV/JSON export. |
| **History** | Tabs: By Search, By Scope, Saved, Audit. |
| **Findings** | Cross-search deduplication — every host counted once with merged CVEs/ports, grouped by Risk/Search/Org/Port, CSV export. |
| **MCP Config** | Autonomy mode (HITL/Scoped/Full), scope enforcement, usage + token-cost meter, external MCP servers. |
| **CVE Intel** | Paste any advisory → extracted CVE IDs, severity, and scoped detection queries. |

The **⚙ Config** dropdown (top-right) has three tabs: **Scope** (multi-tag
builder + free-form query), **API Key** (Shodan key + server URL), **AI Model**
(provider, model picker, key, live cost estimate, test-connection).

---

## Scope configuration

Open **⚙ Config → Scope**. Add any mix of target types:

| Input | Becomes |
|-------|---------|
| `Acme Corp` | `org:"Acme Corp"` |
| `acme.com` | `hostname:acme.com` |
| `203.0.113.0/24` | `net:203.0.113.0/24` |
| `AS64512` | `AS64512` |
| free-form box | appended verbatim (e.g. `http.title:"Login" country:US`) |

All terms combine into one query, shown live in the preview. Scope is stored
server-side, so the console, the crew, and `crewai.bat` all share the same
target. Picking a filter from the builder, and every AI-generated query, is
auto-scoped to this target.

---

## The Nmap recon stage

Sits between passive Shodan recon and the human specialist. It confirms what's
*actually* live (Shodan data can be stale), then produces a ranked hand-off so
the specialist spends intensive-testing time where it matters.

- **Stealthy by default** — SYN scan, `-T2` timing, top-100 ports.
- **Discovery only** — no exploits, no brute force, no intrusive scripts.
- **Scope enforced in code** — refuses to scan any IP outside the active scope.
- **Capped** — max 10 hosts per call, with timeouts.

Toggle it:

```bat
set ENABLE_NMAP=1     REM active scanning ON (default if nmap installed)
set ENABLE_NMAP=0     REM passive Shodan only
```

The triage output ranks hosts HIGH/MEDIUM/LOW and recommends what the
specialist should look at first — the intensive-testing decision stays human.

---

## Autonomy modes

Set in **MCP Config → Settings**, or override on the command line. The mode is
stored server-side and read by `crewai.bat` at startup.

| Mode | Behaviour |
|------|-----------|
| **HITL** (default) | every action requires your `y/n` approval |
| **Scoped** | auto-approves actions within the defined scope |
| **Full Auto** | no prompts; bat asks for written confirmation; audit log always on |

```bat
crewai.bat anthropic          REM mode from the UI
crewai.bat anthropic scoped   REM override to scoped
crewai.bat anthropic full     REM override to full auto
```

---

## MCP server

`core/server.py` exposes a JSON-RPC 2.0 MCP endpoint at
`http://127.0.0.1:8000/mcp` with six tools: `shodan_search`, `get_results`,
`get_scope`, `set_scope`, `get_history`, `cve_intel`.

**Claude Desktop / Cursor / Windsurf:**
```json
{ "mcpServers": { "shodansnipe": { "url": "http://127.0.0.1:8000/mcp" } } }
```

**CrewAI (auto tool discovery):** see `agents/example_crew_mcp.py` — it uses
`MCPServerAdapter` to discover all six tools without writing wrappers.

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | — | Anthropic key (set before running the crew) |
| `OPENAI_API_KEY` | — | OpenAI key |
| `OLLAMA_URL` | `http://localhost:11434/v1` | local Ollama endpoint |
| `LLM_PROVIDER` | `openai` | `anthropic` / `openai` / `ollama` |
| `SHODANSNIPE_URL` | `http://127.0.0.1:8000` | server URL the crew talks to |
| `SHODANSNIPE_PASSPHRASE` | *(prompt)* | DB passphrase — set to skip the prompt |
| `MCP_AUTONOMY_MODE` | `hitl` | `hitl` / `scoped` / `full` |
| `ENABLE_NMAP` | `1` | `0` = passive Shodan only |
| `TARGET_ORG` / `TARGET_SCOPE` | *(from server)* | set automatically by `crewai.bat` |
| `CVE_ADVISORY` | — | optional CVE text for the Vuln Analyst |

Set permanently in PowerShell:
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY","sk-ant-...","User")
```

See `docs/CREWAI_SETUP.md` for the full env-var walkthrough.

---

## Extending the system

Adding a capability is always the same shape:

1. **Tool** — a `BaseTool` in `tools/` (see `skills/BUILDING_TOOLS.md`)
2. **Agent** — a module in `agents/` exporting `build_*_agent` / `build_*_tasks`
   (see `skills/BUILDING_AGENTS.md`)
3. **Wire it** — import and insert into `launchers/poc_crew.py` at the right
   pipeline position
4. **Test in isolation**, then run the full crew

The four agents are your worked examples — copy their shape. Safety rules:
enforce scope in code (not just prompts), return strings from tools (never
raise), and keep destructive/intensive actions under human control.

---

## Troubleshooting

**`Unexpected token` / functions "not defined" in the console**
A stale `static/index.html` is being served. Replace it and hard-refresh
(Ctrl+Shift+R).

**Console can't reach the API / 404 HTML page**
You opened the page from the wrong origin. Use the exact URL the server prints
(`http://127.0.0.1:8000`). Or set the server URL in ⚙ Config → API Key.

**`crewai.bat` shows `LLM: -anthropic`**
Drop the leading dash: `crewai.bat anthropic`, not `-anthropic`.

**Autonomy stuck on HITL after picking Scoped in the UI**
Confirm the server has the endpoint: `curl http://127.0.0.1:8000/api/config/autonomy`.

**`ImportError` for `db`, `scope`, `diff_store`, or `query_advisor`**
These are local `core/` modules. Copy your existing copies into `core/`
alongside `server.py`. See `DEPENDENCIES.md`.

**`[NMAP] disabled` when you expected it on**
Either `ENABLE_NMAP=0` or nmap isn't installed/on PATH. Install nmap or run
passive-only.

**`litellm: could not pre-load bedrock-runtime` warnings**
Harmless — `botocore` isn't installed and you aren't using Bedrock.

---

*Built for SEC598 · SANS Institute · Attack Surface Management + Agentic AI*

