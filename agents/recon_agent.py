"""
recon_agent.py — Attack Surface Reconnaissance Specialist (official team member).

Pipeline role:
    MANAGER → [RECON SPECIALIST] → NMAP RECON → VULN ANALYST → REPORT WRITER

The first responder. Maps the external attack surface via Shodan: finds
internet-facing services, exposed management interfaces, open ports, and
product fingerprints. Sets and confirms scope before anything else runs.

Build with:  build_recon_agent(llm)
Tasks with:  build_recon_tasks(agent, target_org, target_scope)
"""

from crewai import Agent, Task

try:
    from tools.shodansnipe_tools import (
        ShodanSearchTool, SetScopeTool, GetScopeTool,
    )
except ImportError:
    from shodansnipe_tools import (
        ShodanSearchTool, SetScopeTool, GetScopeTool,
    )


def build_recon_agent(llm) -> Agent:
    """Create the Attack Surface Reconnaissance Specialist."""
    return Agent(
        role="Attack Surface Reconnaissance Specialist",
        goal=(
            "Map the external attack surface of the target. Find all "
            "internet-facing services, identify exposed management interfaces, "
            "and catalogue open ports and product fingerprints — all strictly "
            "within the defined scope."
        ),
        backstory=(
            "You are a senior red team operator with 10 years of OSINT and "
            "Shodan experience. You know exactly which Shodan filters surface the "
            "most interesting findings and how to pivot from one result to related "
            "infrastructure. You set scope first and never search outside it. "
            "You use valid Shodan syntax only — no OR/AND/NOT, no wildcards."
        ),
        tools=[ShodanSearchTool(), SetScopeTool(), GetScopeTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=15,
    )


def build_recon_tasks(agent: Agent, target_org: str, target_scope: str) -> list[Task]:
    set_scope_task = Task(
        description=(
            f"Set the active scope to: '{target_scope}'. "
            "Then confirm the scope was set correctly by reading it back with get_scope."
        ),
        expected_output="Confirmation of scope: org name plus any CIDRs/ASNs/domains detected.",
        agent=agent,
    )

    recon_task = Task(
        description=(
            f"Conduct a full Shodan reconnaissance of {target_org} within scope.\n"
            f"Scope query: {target_scope}\n\n"
            "Run a layered set of searches and pivot from what you find:\n"
            f"  1. {target_scope} — general surface scan\n"
            f"  2. {target_scope} port:22,3389,5900,23 — remote access exposure\n"
            f"  3. {target_scope} ssl.cert.expired:true — expired certs\n"
            f"  4. {target_scope} port:443,8443,8080 — web services\n"
            "For each search: note result count, interesting ports, product "
            "versions, and any CVEs Shodan already flagged. Then pivot based on "
            "what actually appeared. Identify the 3-5 most critical findings. "
            "Use valid Shodan syntax only."
        ),
        expected_output=(
            "A structured list of findings: each has an IP/range, service "
            "description, ports, risk level (Critical/High/Medium/Low), and a "
            "one-sentence explanation of why it matters."
        ),
        agent=agent,
        context=[set_scope_task],
    )

    return [set_scope_task, recon_task]
