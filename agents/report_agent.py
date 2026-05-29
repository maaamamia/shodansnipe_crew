"""
report_agent.py — Security Report Writer (official team member).

Pipeline role:
    MANAGER → RECON → NMAP RECON → VULN ANALYST → [REPORT WRITER]

The closer. Synthesises every upstream finding into a concise, prioritised
executive report: risk ratings, affected assets, recommended actions. Writes
for both technical and executive audiences, highest-risk first, no filler.

Build with:  build_report_agent(llm)
Tasks with:  build_report_tasks(agent, prior_tasks)
"""

from crewai import Agent, Task

try:
    from tools.shodansnipe_tools import GetResultsTool, GetHistoryTool
except ImportError:
    from shodansnipe_tools import GetResultsTool, GetHistoryTool


def build_report_agent(llm) -> Agent:
    """Create the Security Report Writer."""
    return Agent(
        role="Security Report Writer",
        goal=(
            "Synthesise all findings into a concise, prioritised executive report "
            "with risk ratings, affected assets, and recommended immediate actions."
        ),
        backstory=(
            "You write clear, precise security reports for both technical and "
            "executive audiences. You lead with the highest-risk findings, you "
            "deduplicate (one host counted once), and you never pad the report "
            "with filler. Every recommended action names an owner and a timeline."
        ),
        tools=[GetResultsTool(), GetHistoryTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,
        max_iter=8,
    )


def build_report_tasks(agent: Agent, prior_tasks: list[Task] | None = None) -> list[Task]:
    ctx = list(prior_tasks) if prior_tasks else []

    report_task = Task(
        description=(
            "Write a concise threat exposure report for the security team. "
            "Use these sections:\n"
            "  1. Executive Summary — 2-3 sentences, plain language\n"
            "  2. Critical Findings — highest risk first, max 5\n"
            "  3. CVE Exposure — from the vulnerability analysis\n"
            "  4. Network Recon Hand-off — the NMAP triage list, if that stage ran\n"
            "  5. Recommended Actions — prioritised, specific, with owner + timeline\n"
            "  6. Monitoring Queries — the most useful Shodan queries for ongoing detection\n"
            "Deduplicate hosts (count each unique IP once). Keep under 700 words."
        ),
        expected_output=(
            "A formatted threat exposure report with the sections above. "
            "Risk ratings use CRITICAL / HIGH / MEDIUM / LOW. Each recommended "
            "action includes who should do it and by when."
        ),
        agent=agent,
        context=ctx,
    )

    return [report_task]
