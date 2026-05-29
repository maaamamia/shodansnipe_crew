"""
nmap_recon_agent.py — Stealthy NMAP reconnaissance & triage agent.

Role in the crew pipeline:

    Shodan RESEARCHER  →  NMAP RECON (this agent)  →  Senior Network Operator (human)

The NMAP recon agent takes the hosts the Shodan researcher confirmed are live
and in-scope, runs stealthy active scans to enumerate real open ports and
service versions (Shodan data can be stale), then produces a PRIORITISED
hand-off list telling the human specialist which hosts to test intensively.

It does discovery and triage ONLY. It never runs exploits, brute force, or
intrusive checks — those are the specialist's job and stay under human control.

Build a fresh agent from this file with:  build_nmap_agent(llm)
Build its tasks with:                      build_nmap_tasks(agent, prior_task)
"""

from crewai import Agent, Task

# Tools live in the tools/ package
try:
    from tools.nmap_tool import NmapDiscoveryTool, NmapTriageTool
    from tools.shodansnipe_tools import GetResultsTool, GetScopeTool
except ImportError:
    # Allow flat-layout import too
    from nmap_tool import NmapDiscoveryTool, NmapTriageTool
    from shodansnipe_tools import GetResultsTool, GetScopeTool


def build_nmap_agent(llm) -> Agent:
    """Create the NMAP reconnaissance agent."""
    return Agent(
        role="Stealthy Network Reconnaissance Specialist",
        goal=(
            "Take the in-scope hosts discovered via Shodan, run stealthy active "
            "Nmap scans to confirm what is REALLY exposed right now, and produce a "
            "prioritised hand-off telling the senior network operator which hosts "
            "deserve intensive manual testing — and why."
        ),
        backstory=(
            "You are a careful reconnaissance operator. Shodan tells you what was "
            "seen at some point in the past; you verify it live with low-and-slow "
            "Nmap scans (SYN scan, polite timing) so you don't trip alarms. "
            "You enumerate open ports and service versions but you NEVER exploit, "
            "brute-force, or run intrusive scripts — that authority belongs to the "
            "senior network operator who comes after you. "
            "Your deliverable is a clear, ranked list: which hosts are worth the "
            "specialist's deep-testing time, which services on them matter, and what "
            "the specialist should look at first. You always stay strictly inside the "
            "defined scope and refuse to scan anything outside it."
        ),
        tools=[NmapDiscoveryTool(), NmapTriageTool(), GetResultsTool(), GetScopeTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=12,
    )


def build_nmap_tasks(agent: Agent, prior_task: Task | None = None) -> list[Task]:
    """
    Build the NMAP recon tasks. If prior_task is supplied (the Shodan recon
    task), its output (the list of live hosts) is used as context.
    """
    ctx = [prior_task] if prior_task else []

    task_scan = Task(
        description=(
            "Read the in-scope hosts found by the Shodan researcher "
            "(call get_current_results if you need the IP list).\n\n"
            "For the most interesting hosts (highest Shodan risk first, max 10 "
            "per batch), run nmap_discovery_scan to confirm which ports are "
            "actually open right now and what service versions are running.\n\n"
            "Stay stealthy: default timing is T2. Do NOT scan anything that is "
            "not in scope — the tool will reject out-of-scope IPs, and you should "
            "not try to bypass that.\n\n"
            "Compare what Nmap finds to what Shodan reported. Note any differences "
            "(ports Shodan missed, services that changed, hosts now offline)."
        ),
        expected_output=(
            "Per-host live scan results: confirmed open ports, service versions, "
            "and any differences from the Shodan data."
        ),
        agent=agent,
        context=ctx,
    )

    task_triage = Task(
        description=(
            "Using nmap_triage_for_specialist on the scanned hosts, produce the "
            "HAND-OFF document for the senior network operator.\n\n"
            "The document must:\n"
            "  1. Rank every scanned host HIGH / MEDIUM / LOW for intensive testing\n"
            "  2. For each HIGH host, state exactly which services warrant deep "
            "testing and what the specialist should try first (in advisory terms — "
            "you are recommending, not performing)\n"
            "  3. Call out any host where the live Nmap picture is materially worse "
            "than Shodan suggested (e.g. extra management ports exposed)\n"
            "  4. End with a one-line summary: how many HIGH hosts, and the single "
            "host you would test first if you only had time for one\n\n"
            "Remember: you are preparing work for a human specialist. Be precise and "
            "actionable, but leave the intensive testing decisions to them."
        ),
        expected_output=(
            "A prioritised hand-off: ranked host list with HIGH/MEDIUM/LOW, "
            "per-host reasoning and recommended specialist focus, and a summary line."
        ),
        agent=agent,
        context=[task_scan],
    )

    return [task_scan, task_triage]
