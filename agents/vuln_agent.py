"""
vuln_agent.py — Vulnerability Intelligence Analyst (official team member).

Pipeline role:
    MANAGER → RECON → NMAP RECON → [VULN ANALYST] → REPORT WRITER

Cross-references known CVEs against the discovered infrastructure, converts
CVE advisories into Shodan detection queries, runs them, and prioritises by
severity. The bridge between "what's exposed" and "what's actually vulnerable".

Build with:  build_vuln_agent(llm)
Tasks with:  build_vuln_tasks(agent, target_org, cve_advisory, prior_task)
"""

from crewai import Agent, Task

try:
    from tools.shodansnipe_tools import (
        CVEIntelTool, ShodanSearchTool, GetResultsTool,
    )
except ImportError:
    from shodansnipe_tools import (
        CVEIntelTool, ShodanSearchTool, GetResultsTool,
    )


def build_vuln_agent(llm) -> Agent:
    """Create the Vulnerability Intelligence Analyst."""
    return Agent(
        role="Vulnerability Intelligence Analyst",
        goal=(
            "Cross-reference known CVEs against the discovered infrastructure. "
            "Generate scoped detection queries for active vulnerabilities and "
            "prioritise findings by severity."
        ),
        backstory=(
            "You are a CISA-trained vulnerability analyst who specialises in "
            "converting CVE advisories into actionable detection signatures. "
            "You understand which Shodan fields reveal vulnerable versions "
            "(product banners, http.component, ssl versions). You scope every "
            "detection query to the target and use valid Shodan syntax only."
        ),
        tools=[CVEIntelTool(), ShodanSearchTool(), GetResultsTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=12,
    )


def build_vuln_tasks(agent: Agent, target_org: str, cve_advisory: str = "",
                     prior_task: Task | None = None) -> list[Task]:
    ctx = [prior_task] if prior_task else []

    advisory_block = (
        f"Analyse the following CVE advisory and generate detection queries "
        f"scoped to {target_org}:\n\n{cve_advisory}\n\n"
        if cve_advisory.strip() else
        f"Review the recon findings for {target_org} and identify the product "
        "versions present. For any version with known CVEs, generate scoped "
        "Shodan detection queries.\n\n"
    )

    cve_task = Task(
        description=(
            advisory_block +
            "Then run the top 2-3 detection queries against Shodan (scoped to the "
            "target). Report how many hosts match and which are highest risk. "
            "Use valid Shodan syntax only — no OR/AND/NOT."
        ),
        expected_output=(
            "CVE summary (ID, severity, affected product/version), list of "
            "detection queries with result counts, and a verdict: is this org "
            "likely EXPOSED / POSSIBLY EXPOSED / NOT DETECTED?"
        ),
        agent=agent,
        context=ctx,
    )

    return [cve_task]
