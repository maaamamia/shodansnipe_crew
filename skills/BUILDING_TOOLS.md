# SKILL: Building Tools

A **tool** is the only way an agent affects the world — it runs a search, scans
a host, queries an API, reads a file. Tools live in `tools/` as `BaseTool`
subclasses. This doc is the convention.

---

## Anatomy of a tool

```python
from typing import Optional, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# 1. Input schema — what the LLM must provide to call the tool
class MyToolInput(BaseModel):
    target: str = Field(description="The thing to act on. Be specific.")
    limit: Optional[int] = Field(default=25, description="Max results.")

# 2. The tool itself
class MyTool(BaseTool):
    name: str = "my_action"                    # snake_case, unique
    description: str = (
        "What it does + what it returns, in 1-3 sentences. "
        "The LLM reads ONLY this to decide whether to call it."
    )
    args_schema: Type[BaseModel] = MyToolInput

    def _run(self, target: str, limit: int = 25) -> str:
        try:
            result = do_the_work(target, limit)
            return format_as_readable_string(result)
        except Exception as e:
            return f"my_action error: {e}"      # NEVER raise
```

---

## The five hard rules

### 1. Always return a string
The LLM reasons over text. Return readable, structured text — not dicts, not
objects. If you have structured data, format it into lines the model can parse.

### 2. Never raise — catch everything
A raised exception breaks the agent's reasoning loop and can crash the run.
Wrap the body in `try/except` and return the error as a string. The agent can
then decide what to do about it.

### 3. Enforce safety in code, not in the prompt
If a tool should only act in-scope, check scope **inside `_run`** and refuse if
violated. Do not trust the LLM to respect a boundary you only stated in the
prompt. Example from `nmap_tool.py`:

```python
in_scope = [ip for ip in ip_list if _ip_in_scope(ip, scope)]
if not in_scope:
    return f"Refusing — all targets out of scope: {rejected}"
```

### 4. Description quality = tool usage quality
The `description` is the entire basis on which the LLM decides to call your
tool. Vague description → tool ignored or misused. State what it does, what it
returns, and any important constraints (e.g. "max 10 targets per call").

### 5. Cap expensive operations
If a tool can trigger something slow or noisy (a big scan, a paid API call),
cap it in code: `_MAX_HOSTS_PER_CALL`, timeouts, result limits. Don't let a
single LLM call kick off something unbounded.

---

## Talking to the ShodanSnipe server

Most tools call the running server. Use the shared helpers:

```python
import os, requests
SHODANSNIPE_URL = os.getenv("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/")

def _get(path, timeout=30):
    r = requests.get(f"{SHODANSNIPE_URL}{path}", timeout=timeout)
    r.raise_for_status()
    return r.json()

def _post(path, body, timeout=180):
    r = requests.post(f"{SHODANSNIPE_URL}{path}", json=body, timeout=timeout)
    r.raise_for_status()
    return r.json()
```

---

## Shelling out to external binaries (like nmap)

When a tool wraps a CLI tool:

```python
import shutil, subprocess
_BIN = shutil.which("nmap")

def _run(self, ...):
    if not _BIN:
        return "nmap not installed. Install: ..."     # graceful, not a crash
    try:
        proc = subprocess.run([_BIN, ...], capture_output=True,
                              text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "scan timed out"
    return parse(proc.stdout)
```

- Check the binary exists with `shutil.which` and return a helpful message if not.
- Always set a `timeout`.
- Parse output into clean text — don't dump raw CLI output on the LLM.

---

## Registering the tool with an agent

In the agent file, import and instantiate:

```python
from tools.my_tool import MyTool
agent = Agent(..., tools=[MyTool(), OtherTool()])
```

That's it — CrewAI exposes `name`, `description`, and `args_schema` to the LLM
automatically.

---

## Checklist for a new tool

```
[ ] BaseTool subclass with name, description, args_schema
[ ] Pydantic input schema with Field descriptions
[ ] _run returns a string in every code path
[ ] Every path wrapped so it never raises
[ ] Safety/scope enforced in code
[ ] Expensive operations capped (timeout, max items)
[ ] External binaries checked with shutil.which + graceful message
[ ] description tells the LLM exactly when & why to use it
```
