# The Crew — Official Team Roster

Every agent is a standalone module in `agents/`. Each is reusable, testable in
isolation, and assembled into the pipeline by the orchestrator
(`launchers/poc_crew.py` OR `launchers/crewai.bat`).
---

## The pipeline at a glance

```
   ┌──────────────────────────────────────────────────────────────┐
   │                        MANAGER                                 │
   │            Crew Manager & Scope Enforcer                       │
   │  validates scope · enforces order · dedups · final report     │
   └───────┬──────────────────────────────────────────────────────┘
           │ delegates, in order:
           ▼
   ┌──────────────────────────┐
   │  1. RECON SPECIALIST      │  agents/recon_agent.py
   │  Attack Surface Recon     │  tools: shodan_search, set_scope, get_scope
   │  "what's exposed?"        │  → list of in-scope live hosts + risk
   └───────────┬──────────────┘
               ▼
   ┌──────────────────────────┐
   │  2. NMAP RECON            │  agents/nmap_recon_agent.py
   │  Stealthy Network Recon   │  tools: nmap_discovery_scan,
   │  "confirm live + triage"  │         nmap_triage_for_specialist
   │                           │  → HIGH/MED/LOW hand-off list
   └───────────┬──────────────┘
               │  hand-off ↓
               ▼
   ┌──────────────────────────┐
   │  3. VULN ANALYST          │  agents/vuln_agent.py
   │  Vulnerability Intel      │  tools: cve_intel, shodan_search, get_results
   │  "what's vulnerable?"     │  → CVE detection queries + exposure verdict
   └───────────┬──────────────┘
               ▼
   ┌──────────────────────────┐
   │  4. REPORT WRITER         │  agents/report_agent.py
   │  Security Report Writer   │  tools: get_results, get_history
   │  "tell the story"         │  → executive threat exposure report
   └──────────────────────────┘
```

---

## Roster cards

### MANAGER — Crew Manager & Scope Enforcer
*Defined in `launchers/poc_crew.py` (orchestrator-only role)*
- **Job:** confirm scope before anything runs, enforce run order, ensure
  deduplication, write the final prioritised report.
- **Tools:** set_scope, get_scope, get_history
- **Can delegate:** yes (the only agent that can).

### 1. RECON SPECIALIST — `agents/recon_agent.py`
- **Job:** map the external attack surface via Shodan; set & confirm scope first.
- **Tools:** `shodan_search`, `set_scope`, `get_scope`
- **Output:** structured findings — IP/range, services, ports, risk level.
- **Build:** `build_recon_agent(llm)` / `build_recon_tasks(agent, org, scope)`

### 2. NMAP RECON — `agents/nmap_recon_agent.py`
- **Job:** stealthy active scan to confirm what's *really* live (Shodan can be
  stale), then triage HIGH/MEDIUM/LOW for the human specialist.
- **Tools:** `nmap_discovery_scan`, `nmap_triage_for_specialist`, `get_results`, `get_scope`
- **Boundaries:** discovery & enumeration only — no exploits, no brute force.
  Scope enforced in code. Intensive testing decisions stay with the human.
- **Build:** `build_nmap_agent(llm)` / `build_nmap_tasks(agent, prior_task)`

### 3. VULN ANALYST — `agents/vuln_agent.py`
- **Job:** cross-reference CVEs against discovered infrastructure, generate
  scoped detection queries, prioritise by severity.
- **Tools:** `cve_intel`, `shodan_search`, `get_results`
- **Output:** CVE summary + detection queries + EXPOSED/POSSIBLY/NOT verdict.
- **Build:** `build_vuln_agent(llm)` / `build_vuln_tasks(agent, org, cve, prior_task)`

### 4. REPORT WRITER — `agents/report_agent.py`
- **Job:** synthesise everything into a concise executive report, highest risk
  first, deduplicated, each action with owner + timeline.
- **Tools:** `get_results`, `get_history`
- **Output:** the final threat exposure report.
- **Build:** `build_report_agent(llm)` / `build_report_tasks(agent, prior_tasks)`

---

## Running the team

**Full production pipeline** (Manager + Recon + NMAP + Vuln + Report):
```bash
cd launchers && crewai.bat anthropic
```

**Minimal reference crew** (Recon → Vuln → Report):
```bash
python agents/example_crew.py
```

**One agent in isolation** (test or visualise a single member):
```python
from recon_agent import build_recon_agent, build_recon_tasks
from crewai import Crew, Process, LLM
llm = LLM(model="gpt-4o-mini")
agent = build_recon_agent(llm)
tasks = build_recon_tasks(agent, "Dell", 'org:"Dell"')
Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=True).kickoff()
```

---

## Adding a new team member

Follow `skills/BUILDING_AGENTS.md`. The shape is always the same:
one file in `agents/`, exporting `build_<name>_agent(llm)` and
`build_<name>_tasks(agent, ...)`, then wired into `launchers/poc_crew.py` at
the right pipeline position. The four agents above are your worked examples.
