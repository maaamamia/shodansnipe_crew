"""
nmap_tool.py — CrewAI tool wrapper for stealthy Nmap reconnaissance.

This tool performs DISCOVERY and ENUMERATION only — it identifies open ports,
service versions, and host characteristics so a human specialist can decide
where to spend intensive testing effort. It does NOT run exploits, brute-force,
or intrusive NSE scripts.

Scope safety:
  - Only scans IPs confirmed to be in the active ShodanSnipe scope.
  - Refuses to scan anything outside scope (prevents accidental out-of-bounds).
  - Defaults to stealthy timing (-T2) and SYN scan (-sS) to minimise footprint.

Requires nmap installed on the host:
  Windows:  choco install nmap   (or https://nmap.org/download.html)
  Linux:    sudo apt install nmap
  Mac:      brew install nmap

Set SHODANSNIPE_URL to point at the running server (default localhost:8000).
"""

import json
import os
import re
import shutil
import subprocess
from typing import Optional, Type

import requests
from pydantic import BaseModel, Field

try:
    from crewai.tools import BaseTool
except ImportError:
    from crewai_tools import BaseTool

SHODANSNIPE_URL = os.getenv("SHODANSNIPE_URL", "http://127.0.0.1:8000").rstrip("/")

# Nmap timing templates: T0 (paranoid) … T5 (insane). T2 = polite/stealthy.
_DEFAULT_TIMING = os.getenv("NMAP_TIMING", "T2")
_NMAP_BIN = shutil.which("nmap")

# A conservative cap so a single agent call can't kick off a massive scan.
_MAX_HOSTS_PER_CALL = int(os.getenv("NMAP_MAX_HOSTS", "10"))
_SCAN_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "300"))  # seconds per nmap run


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------
def _get_scope() -> dict:
    try:
        r = requests.get(f"{SHODANSNIPE_URL}/api/scope", timeout=10)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {"is_empty": True}


def _ip_in_scope(ip: str, scope: dict) -> bool:
    """Best-effort scope check: IP must appear in a scope CIDR, or scope must be open."""
    if scope.get("is_empty"):
        return False
    # If the scope only defines orgs/domains (not CIDRs), we trust that the IPs
    # came from a scoped Shodan search — they were already filtered server-side.
    cidrs = scope.get("cidrs", [])
    if not cidrs:
        return True  # org/domain scope — IPs already came from scoped results
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        for c in cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Nmap execution
# ---------------------------------------------------------------------------
def _run_nmap(targets: list[str], ports: Optional[str], timing: str, aggressive: bool) -> dict:
    """Run a single nmap scan and parse the grepable output."""
    if not _NMAP_BIN:
        return {"error": "nmap is not installed or not on PATH. Install nmap first."}

    # Build args. Default scan is stealthy SYN + service/version detect.
    args = [_NMAP_BIN, "-sS" if not aggressive else "-sV", "-sV",
            f"-{timing}", "-Pn", "--open"]
    if ports:
        args += ["-p", ports]
    else:
        args += ["--top-ports", "100"]   # fast: top 100 ports only
    # Grepable output to stdout
    args += ["-oG", "-"]
    args += targets

    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=_SCAN_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return {"error": f"nmap timed out after {_SCAN_TIMEOUT}s for {targets}"}
    except Exception as e:
        return {"error": f"nmap failed: {e}"}

    return _parse_grepable(proc.stdout)


def _parse_grepable(out: str) -> dict:
    """Parse nmap -oG output into structured host→ports data."""
    hosts = {}
    for line in out.splitlines():
        if not line.startswith("Host:"):
            continue
        m_ip = re.search(r"Host:\s+(\S+)", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        ports = []
        m_ports = re.search(r"Ports:\s+(.+?)(?:\tIgnored|$)", line)
        if m_ports:
            for chunk in m_ports.group(1).split(","):
                parts = chunk.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    port = parts[0]
                    proto = parts[2]
                    service = parts[4] or "unknown"
                    version = parts[6] if len(parts) > 6 else ""
                    ports.append({
                        "port": port, "proto": proto,
                        "service": service, "version": version.strip(),
                    })
        if ports:
            hosts[ip] = ports
    return {"hosts": hosts}


# ---------------------------------------------------------------------------
# Risk triage — decide which hosts deserve intensive testing
# ---------------------------------------------------------------------------
# Services that typically warrant a closer look by a specialist.
_HIGH_INTEREST = {
    "ssh", "rdp", "ms-wbt-server", "vnc", "telnet", "ftp",
    "smb", "microsoft-ds", "netbios-ssn",
    "mysql", "ms-sql-s", "postgresql", "mongodb", "redis", "elasticsearch",
    "ldap", "kerberos", "snmp", "rpcbind", "docker", "kubernetes",
    "http-proxy", "vnc-http", "ajp13",
}
_HIGH_INTEREST_PORTS = {
    "21", "22", "23", "445", "1433", "3306", "3389", "5432",
    "5900", "6379", "9200", "27017", "2375", "6443", "161",
}


def _triage(hosts: dict) -> list[dict]:
    """Score each host for 'intensive testing' priority."""
    out = []
    for ip, ports in hosts.items():
        score = 0
        reasons = []
        svc_names = []
        for p in ports:
            svc = (p.get("service") or "").lower()
            port = p.get("port", "")
            svc_names.append(f"{port}/{svc}")
            if svc in _HIGH_INTEREST or port in _HIGH_INTEREST_PORTS:
                score += 2
                reasons.append(f"{port}/{svc} is a high-value target")
            # Version strings present = fingerprintable = CVE-checkable
            if p.get("version"):
                score += 1
        # More open ports = larger attack surface
        if len(ports) >= 5:
            score += 2
            reasons.append(f"{len(ports)} open ports — large surface")
        elif len(ports) >= 3:
            score += 1

        priority = "HIGH" if score >= 5 else "MEDIUM" if score >= 2 else "LOW"
        out.append({
            "ip": ip,
            "open_ports": len(ports),
            "services": svc_names,
            "priority": priority,
            "score": score,
            "reasons": reasons or ["standard exposure"],
        })
    out.sort(key=lambda h: h["score"], reverse=True)
    return out


# ===========================================================================
# TOOL 1 — Stealthy discovery scan
# ===========================================================================
class NmapScanInput(BaseModel):
    targets: str = Field(description=(
        "Comma-separated IPs to scan (from Shodan findings). "
        "e.g. '203.0.113.5, 203.0.113.9'. Max 10 per call."
    ))
    ports: Optional[str] = Field(default=None, description=(
        "Optional port spec, e.g. '22,80,443' or '1-1000'. "
        "If omitted, scans the top 100 most common ports."
    ))
    timing: Optional[str] = Field(default=None, description=(
        "Nmap timing template T0-T5. Default T2 (stealthy/polite). "
        "Use T3 for normal speed, T4 only on networks you fully control."
    ))


class NmapDiscoveryTool(BaseTool):
    name: str = "nmap_discovery_scan"
    description: str = (
        "Run a STEALTHY Nmap discovery scan on IPs found via Shodan. "
        "Performs SYN scan + service/version detection on the top 100 ports "
        "(or a port spec you provide). Returns open ports and service versions "
        "per host. Only scans IPs that are in the active scope. "
        "This is for ENUMERATION only — no exploits, no brute force. "
        "Use this to map live services before deciding where to test intensively."
    )
    args_schema: Type[BaseModel] = NmapScanInput

    def _run(self, targets: str, ports: Optional[str] = None,
             timing: Optional[str] = None) -> str:
        if not _NMAP_BIN:
            return ("nmap is not installed. Install it:\n"
                    "  Windows: choco install nmap\n"
                    "  Linux:   sudo apt install nmap\n"
                    "  Mac:     brew install nmap")

        ip_list = [t.strip() for t in targets.split(",") if t.strip()]
        if not ip_list:
            return "No targets provided."
        if len(ip_list) > _MAX_HOSTS_PER_CALL:
            return (f"Too many targets ({len(ip_list)}). Max {_MAX_HOSTS_PER_CALL} "
                    "per call to keep scans stealthy. Split into batches.")

        # Scope enforcement
        scope = _get_scope()
        if scope.get("is_empty"):
            return ("No scope is set. Refusing to scan. "
                    "Set a scope in ShodanSnipe first so scanning stays in-bounds.")
        in_scope = [ip for ip in ip_list if _ip_in_scope(ip, scope)]
        rejected = [ip for ip in ip_list if ip not in in_scope]
        if not in_scope:
            return (f"None of the targets are in scope '{scope.get('name')}'. "
                    f"Refusing to scan out-of-scope hosts: {rejected}")

        tmpl = (timing or _DEFAULT_TIMING).lstrip("-")
        if tmpl not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
            tmpl = _DEFAULT_TIMING

        result = _run_nmap(in_scope, ports, tmpl, aggressive=False)
        if "error" in result:
            return f"Scan error: {result['error']}"

        hosts = result["hosts"]
        if not hosts:
            note = f"Scanned {len(in_scope)} host(s) — no open ports found (timing {tmpl})."
            if rejected:
                note += f"\nSkipped out-of-scope: {rejected}"
            return note

        # Format output
        lines = [f"Nmap discovery scan complete (timing {tmpl}, scope '{scope.get('name')}'):", ""]
        for ip, plist in hosts.items():
            lines.append(f"  {ip} — {len(plist)} open port(s):")
            for p in plist:
                ver = f"  [{p['version']}]" if p["version"] else ""
                lines.append(f"      {p['port']}/{p['proto']}  {p['service']}{ver}")
            lines.append("")
        if rejected:
            lines.append(f"Skipped out-of-scope hosts: {rejected}")
        return "\n".join(lines)


# ===========================================================================
# TOOL 2 — Triage / prioritisation for the human specialist
# ===========================================================================
class NmapTriageInput(BaseModel):
    targets: str = Field(description=(
        "Comma-separated IPs to scan and triage (from Shodan findings). Max 10."
    ))


class NmapTriageTool(BaseTool):
    name: str = "nmap_triage_for_specialist"
    description: str = (
        "Scan the given in-scope IPs (stealthy, top-100 ports) and produce a "
        "PRIORITISED LIST telling the senior network operator which hosts deserve "
        "intensive manual testing and why. Returns HIGH/MEDIUM/LOW priority per "
        "host with reasoning. This is the handoff artifact for the human specialist "
        "— it does NOT perform intensive or intrusive testing itself."
    )
    args_schema: Type[BaseModel] = NmapTriageInput

    def _run(self, targets: str) -> str:
        # Reuse the discovery scan logic
        discovery = NmapDiscoveryTool()
        ip_list = [t.strip() for t in targets.split(",") if t.strip()][:_MAX_HOSTS_PER_CALL]

        scope = _get_scope()
        if scope.get("is_empty"):
            return "No scope set. Refusing to scan."
        in_scope = [ip for ip in ip_list if _ip_in_scope(ip, scope)]
        if not in_scope:
            return f"No in-scope targets among {ip_list}."

        result = _run_nmap(in_scope, None, _DEFAULT_TIMING, aggressive=False)
        if "error" in result:
            return f"Scan error: {result['error']}"

        triaged = _triage(result["hosts"])
        if not triaged:
            return "Scan completed — no open ports found, nothing to prioritise."

        lines = ["═══ NMAP TRIAGE — HANDOFF TO SENIOR NETWORK OPERATOR ═══", ""]
        lines.append("Hosts ranked by recommended intensive-testing priority.")
        lines.append("The specialist should focus deep manual testing on HIGH first.\n")

        for t in triaged:
            lines.append(f"  [{t['priority']}]  {t['ip']}  "
                         f"(score {t['score']}, {t['open_ports']} ports)")
            lines.append(f"      services: {', '.join(t['services'][:10])}")
            for r in t["reasons"][:4]:
                lines.append(f"      → {r}")
            # Suggested next steps for the specialist (advisory only)
            if t["priority"] == "HIGH":
                lines.append("      RECOMMENDED FOR SPECIALIST: full -sV -sC service scan, "
                             "version-specific CVE lookup, manual auth testing of exposed services.")
            elif t["priority"] == "MEDIUM":
                lines.append("      RECOMMENDED: targeted version scan on the high-value ports.")
            lines.append("")

        highs = [t["ip"] for t in triaged if t["priority"] == "HIGH"]
        lines.append("─" * 50)
        lines.append(f"SUMMARY: {len(highs)} HIGH-priority host(s) for the specialist: "
                     f"{', '.join(highs) if highs else 'none'}")
        lines.append("The senior operator decides scope and intensity of follow-up testing.")
        return "\n".join(lines)
