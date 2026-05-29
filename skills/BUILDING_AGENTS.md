# SKILL: Building & Adding Agents

This skill describes the repeatable pattern for adding a new agent to the
ShodanSnipe crew. Follow it whenever you want a new capability (a new scanner,
a new analysis step, a new data source).

---

## The mental model

The crew is a **pipeline of specialists**, each one handing off to the next:

```
MANAGER ─ validates scope, enforces order, writes final report
   │
   ├─ SHODAN RESEARCHER ─ passive recon: what's exposed on the internet
   │
   ├─ NMAP RECON ──────── active recon: confirm live, triage for specialist
   │
   ├─ ANALYST ─────────── threat intel: MITRE mapping, risk verdict
   │
   └─ (your new agent) ── ???
```

Each agent has:
1. **One clear role** — a single job it does well
2. **Tools** — the functions it can call (in `tools/`)
3. **Tasks** — the ordered steps it performs, with `context` linking to the
   previous agent's output

---

## Folder layout

```
shodansnipe/
├── core/          ← engine: server, query execution, LLM client, DB
│   ├── server.py
│   ├── shodansnipe_core.py
│   ├── llm.py
│   └── threat_feeds.py
│
├── agents/        ← one file per agent (role + tasks)
│   ├── nmap_recon_agent.py
│   └── <your_new_agent>.py        ← ADD NEW AGENTS HERE
│
├── tools/         ← CrewAI BaseTool wrappers (the agents' capabilities)
│   ├── shodansnipe_tools.py
│   ├── nmap_tool.py
│   └── <your_new_tool>.py         ← ADD NEW TOOLS HERE
│
├── skills/        ← these docs — the "how to extend" knowledge
│   ├── BUILDING_AGENTS.md          ← this file
│   └── BUILDING_TOOLS.md
│
├── launchers/     ← entry points
│   ├── poc_crew.py                ← the orchestrator that wires agents together
│   ├── crewai.bat
│   └── setup_crewai.bat
│
├── static/
│   └── index.html                 ← web console
│
└── docs/
    ├── README.md
    ├── CREWAI_SETUP.md
    └── sec598_submission.md
```

---

## Step 1 — Build the tool(s)

A tool is a `BaseTool` subclass with a Pydantic input schema. It is the only
way an agent touches the outside world. Put it in `tools/`.

```python
# tools/example_tool.py
from typing import Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

class ExampleInput(BaseModel):
    target: str = Field(description="What to act on")

class ExampleTool(BaseTool):
    name: str = "example_action"
    description: str = (
        "One or two sentences the LLM reads to decide WHEN to call this. "
        "Be specific about what it does and what it returns."
    )
    args_schema: Type[BaseModel] = ExampleInput

    def _run(self, target: str) -> str:
        # Do the work. ALWAYS return a string the LLM can reason about.
        # ALWAYS catch exceptions and return them as text, never raise.
        try:
            ...
            return "structured, readable result"
        except Exception as e:
            return f"example_action error: {e}"
```

**Rules for tools:**
- Return strings, never raise — a raised exception kills the agent loop.
- Enforce scope/safety inside the tool, not just in the prompt. The NMAP tool
  refuses out-of-scope IPs in code; don't rely on the LLM to behave.
- Keep the `description` tight and accurate — it's how the LLM decides to use it.

See `BUILDING_TOOLS.md` for the full convention.

---

## Step 2 — Build the agent

One file per agent in `agents/`. Export two functions:
`build_<name>_agent(llm)` and `build_<name>_tasks(agent, prior_task)`.

```python
# agents/example_agent.py
from crewai import Agent, Task
from tools.example_tool import ExampleTool

def build_example_agent(llm) -> Agent:
    return Agent(
        role="Short Role Title",
        goal="One sentence: what this agent is trying to achieve.",
        backstory=(
            "2-4 sentences. Give it expertise and BOUNDARIES. "
            "State explicitly what it must NOT do (e.g. no exploitation)."
        ),
        tools=[ExampleTool()],
        llm=llm,
        verbose=True,
        allow_delegation=False,   # True only for a manager/orchestrator
        max_iter=12,              # cap the reasoning loop
    )

def build_example_tasks(agent, prior_task=None):
    ctx = [prior_task] if prior_task else []
    t1 = Task(
        description="Step-by-step instructions. Reference tools by name.",
        expected_output="Exactly what the output should contain.",
        agent=agent,
        context=ctx,             # ← links to the previous agent's output
    )
    return [t1]
```

**Rules for agents:**
- One role, one job. If you're writing "and also" in the role, split it.
- `backstory` is where you encode behaviour and limits. Be explicit about what
  the agent may NOT do.
- `max_iter` caps runaway loops. 5-6 for analysis, 12-20 for tool-heavy recon.
- `allow_delegation=True` only for the Manager. Workers don't delegate.
- Chain tasks with `context=[prior_task]` — that's how data flows down the pipeline.

---

## Step 3 — Wire it into the orchestrator

In `launchers/poc_crew.py`, import your agent and insert it into the pipeline
where it belongs:

```python
from agents.example_agent import build_example_agent, build_example_tasks

# inside build_crew(...)
example_agent = build_example_agent(llm)
example_tasks = build_example_tasks(example_agent, prior_task=task_recon)

crew = Crew(
    agents=[manager_agent, researcher_agent, example_agent, analyst_agent],
    tasks=[task_validate, task_recon, *example_tasks, task_intel, task_report],
    process=Process.sequential,   # order = pipeline order
    verbose=True,
)
```

The order of `tasks` IS the execution order. Put your new tasks where they make
sense in the flow.

---

## Step 4 — Test it in isolation first

Before adding to the full crew, run the agent alone:

```python
from crewai import Crew, Process
from agents.example_agent import build_example_agent, build_example_tasks

llm = build_llm()  # from poc_crew
agent = build_example_agent(llm)
tasks = build_example_tasks(agent)
Crew(agents=[agent], tasks=tasks, process=Process.sequential, verbose=True).kickoff()
```

If it works alone, it'll work in the pipeline.

---

## Checklist for a new agent

```
[ ] Tool(s) created in tools/, return strings, catch all exceptions
[ ] Tool enforces scope/safety in code, not just prompt
[ ] Agent has ONE clear role
[ ] backstory states explicit boundaries (what it must NOT do)
[ ] max_iter set appropriately
[ ] Tasks chained with context=[prior_task]
[ ] expected_output describes the deliverable precisely
[ ] Tested in isolation before adding to the crew
[ ] Inserted into poc_crew.py tasks list in the right pipeline position
```
