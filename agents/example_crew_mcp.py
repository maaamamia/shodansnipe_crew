"""
example_crew_mcp.py — ShodanSnipe + CrewAI using the MCP adapter.

CrewAI's MCPServerAdapter connects to ShodanSnipe's /mcp endpoint
and auto-discovers all tools (shodan_search, get_results, cve_intel, etc.)
without you writing any tool wrappers.

Requires crewai >= 0.86 (MCPServerAdapter added in that version).

Usage:
    pip install "crewai[mcp]" requests
    python server.py                    # ShodanSnipe running at :8000
    python example_crew_mcp.py

If crewai[mcp] isn't available yet on your version, use example_crew.py
with the custom tools instead.
"""

import os

try:
    from crewai import Agent, Crew, Process, Task
    from crewai.mcp import MCPServerAdapter
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


SHODANSNIPE_MCP_URL = os.getenv("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/") + "/mcp"


def run_mcp_crew():
    if not MCP_AVAILABLE:
        print("MCPServerAdapter not available in this crewai version.")
        print("Use example_crew.py with the custom BaseTool wrappers instead.")
        return

    # MCPServerAdapter discovers tools from the /mcp endpoint automatically.
    # ShodanSnipe exposes: shodan_search, get_results, get_scope, set_scope,
    #                      get_history, cve_intel
    with MCPServerAdapter({"url": SHODANSNIPE_MCP_URL}) as snipe_tools:
        print(f"Discovered {len(snipe_tools)} tools from ShodanSnipe:")
        for t in snipe_tools:
            print(f"  - {t.name}")

        analyst = Agent(
            role="Threat Intelligence Analyst",
            goal="Identify exposed infrastructure and active CVE exposure for the target.",
            backstory=(
                "You are a defensive security analyst using ShodanSnipe to discover "
                "and prioritise external attack surface risks."
            ),
            tools=snipe_tools,  # all tools auto-discovered from /mcp
            verbose=True,
        )

        hunt = Task(
            description=(
                "1. Set scope to 'Acme Corp'\n"
                "2. Search for: org:\"Acme Corp\" port:443,80,8080,8443\n"
                "3. Search for: org:\"Acme Corp\" ssl.cert.expired:true\n"
                "4. Analyse this advisory with cve_intel:\n"
                "   CVE-2024-1234: Remote code execution in FortiGate SSL-VPN. "
                "   Affects FortiOS 7.0-7.2. CVSS 9.8 Critical.\n"
                "5. Write a 3-paragraph summary of what you found."
            ),
            expected_output=(
                "Scope confirmation, search result summaries, "
                "CVE detection queries, and a findings summary."
            ),
            agent=analyst,
        )

        crew = Crew(
            agents=[analyst],
            tasks=[hunt],
            process=Process.sequential,
            verbose=True,
        )

        result = crew.kickoff()
        print("\nResult:\n", result)


if __name__ == "__main__":
    run_mcp_crew()
