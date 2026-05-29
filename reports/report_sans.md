# ShodanSnipe Threat Report — SANS

Scope confirmed. All findings are within `org:"sans"` / `hostname:sans.org`. Proceeding to compile the final consolidated report.

---

## Executive Summary

An external reconnaissance of SANS's `sans.org` infrastructure revealed a heavily CDN-abstracted attack surface with two critical origin servers bypassing CDN/WAF protections entirely. The most urgent finding is `dashboards.odin.devlabs.sans.org` (3.238.182.230) — a developer dashboard directly exposed on the public internet carrying four active CVEs, no confirmed WAF, and no CDN layer. Compounding this, a `*.sans.org` wildcard SSL certificate is deployed across five separate third-party providers, meaning a single provider compromise could enable impersonation of the entire SANS namespace, placing student data, training platforms, and instructor credentials at immediate risk.

---

## Critical Findings

**1. Exposed DevLabs Dashboard with 4 Active CVEs — CRITICAL**
- **Asset:** `dashboards.odin.devlabs.sans.org` — `3.238.182.230` (Amazon Data Services NoVa)
- **Exposure:** Ports 80/443 publicly reachable, no CDN or WAF confirmed in path; CVE-2025-12141, CVE-2025-4123, CVE-2026-21720, CVE-2026-21721 fingerprinted
- **Risk Level:** CRITICAL
- **Why It Matters:** "Odin.devlabs" naming convention indicates internal DevOps orchestration or secrets management tooling. Direct internet exposure with four live CVEs means this host is already indexable by automated CVE-to-host correlation tools used by ransomware affiliates and APT29/Midnight Blizzard — both of whom specifically target developer infrastructure for credential and cloud token harvesting.

**2. Wildcard Cert `*.sans.org` Deployed Across 5 Third-Party Providers — CRITICAL**
- **Asset:** `*.sans.org` SSL certificate (CloudFront, Akamai, Incapsula, NTT DATA, AWS Direct)
- **Exposure:** Single wildcard cert shared across 5 independent infrastructure providers with no cert pinning observed
- **Risk Level:** CRITICAL
- **Why It Matters:** Compromise or misissue at any one provider grants impersonation rights over every `sans.org` subdomain — training portals, GIAC, NetWars, and student-facing platforms. Maps directly to MITRE T1608.003 and T1584.001.

**3. Bare Apache Origin Server via Third-Party Provider (NTT DATA) — HIGH**
- **Asset:** `ep.sans.org` — `160.109.226.11` (NTT DATA Services Holdings)
- **Exposure:** Apache httpd with visible product banner, ports 80/443, no CDN or WAF confirmed; third-party managed services provider introduces supply chain risk
- **Risk Level:** HIGH
- **Why It Matters:** Version-visible Apache is trivially fingerprintable for known exploits. No CDN abstraction means direct origin exploitation is possible. NTT DATA dependency introduces T1199 (Trusted Relationship) risk — SANS's controls do not extend to the provider's network boundary.

**4. Incapsula WAF Cluster Exposing Anomalous Ports (FTP/SMTP) — HIGH**
- **Asset:** Incapsula/Imperva WAF nodes — `45.60.31.34`, `45.60.33.34`, `45.60.35.34`, `45.60.39.34`
- **Exposure:** Ports 11, 21, 25, 43, 53, 80–84, 88 open; `*.sans.org` cert present; port 21 (FTP) and 25 (SMTP) anomalous for WAF infrastructure
- **Risk Level:** HIGH
- **Why It Matters:** FTP and SMTP on WAF nodes suggests mail or file-transfer infrastructure may be proxied — potentially misconfigured. Open relay or FTP misconfig here could enable data exfiltration or phishing pivots under a trusted `sans.org` cert.

**5. Affiliate Domain `360.leadershiplanding.com` Sharing SANS Wildcard SSL Cert — MEDIUM**
- **Asset:** Akamai nodes serving `360.leadershiplanding.com` under `*.sans.org` cert
- **Exposure:** Third-party affiliate or co-hosted domain in same cert trust chain as SANS primary namespace
- **Risk Level:** MEDIUM
- **Why It Matters:** Affiliate domains typically have weaker security postures. If this domain becomes unmaintained, it becomes a subdomain takeover or cert impersonation vector. Classic supply-chain lateral pivot for threat actors.



---

## Threat Intelligence

Assessment by Dynamic Threat Intelligence Analyst (TLP:AMBER):

The exposure profile maps to **T1190** (Exploit Public-Facing Application) as the primary initial access vector for both `3.238.182.230` and `160.109.226.11`. The DevLabs dashboard additionally maps to **T1133** (External Remote Services) if it exposes any authenticated management UI. The Salesforce click-tracking endpoint enables **T1598.003** (Spearphishing Link) — SANS's Salesforce mail infrastructure is fingerprintable, making cloned phishing campaigns against course registrants operationally trivial. The wildcard cert deployment maps to **T1608.003** and **T1584.001**. NTT DATA and Incapsula dependencies constitute **T1199** (Trusted Relationship) risk.

No active Cobalt Strike, C2, or post-compromise indicators were surfaced. However, the profile is consistent with pre-exploitation reconnaissance used by **UNC2452/Midnight Blizzard (APT29)** and **Scattered Spider (UNC3944)** — both clusters specifically target developer dashboards and CI/CD tooling for lateral movement into cloud IAM and secrets managers. The anomalous hostname `chemveric.com` resolving through a SANS-adjacent AWS ELB warrants separate threat hunting as a potential domain-fronting (**T1090.004**) or compromised-affiliate indicator. Overall risk score: **HIGH-CRITICAL**. Shodan's `0` risk scores reflect enrichment limitations only — not actual host safety.

---

## Pivot Opportunities

**Pivot 1:** `hostname:devlabs.sans.org port:80,443,8080,8443,9200,6443`
Expands the `odin.devlabs` namespace to surface additional management-tier nodes (e.g., `api.odin`, `jenkins.odin`, `monitoring.odin`) that may share the same direct-exposure and CVE profile as the confirmed critical host.

**Pivot 2:** `org:"NTT DATA Services" ssl.cert.subject.cn:"sans.org" product:"Apache httpd"`
Hunts all NTT DATA-hosted Apache servers sharing the `*.sans.org` cert to determine whether `ep.sans.org` is the only unprotected SANS origin or part of a broader unguarded server estate with version-exploitable Apache.

**Pivot 3:** `ssl.cert.subject.cn:"360.leadershiplanding.com"`
Pivots on the affiliate domain confirmed sharing SANS's wildcard cert to map its full infrastructure footprint and assess whether its security posture is weaker than the primary SANS surface — a classic supply-chain lateral entry path.

---

## Recommended Actions

**1. Emergency isolation of `dashboards.odin.devlabs.sans.org` (3.238.182.230)**
- **Who:** Cloud/Infrastructure Security Team
- **Timeline:** Within 2 hours
- Restrict AWS security group to known corporate IP ranges or place behind VPN gateway immediately. Identify the running application, confirm authentication state, and cross-reference CVE-2025-12141, CVE-2025-4123, CVE-2026-21720, CVE-2026-21721 against the actual software stack.

**2. Conduct full vulnerability assessment of `ep.sans.org` (160.109.226.11)**
- **Who:** Application Security Team + NTT DATA account manager
- **Timeline:** Within 24 hours
- Retrieve exact Apache version from banner, cross-reference against known CVEs, confirm whether a WAF or reverse proxy should be placed in front, and validate NTT DATA's patch SLA for this host.

**3. Audit and remediate `*.sans.org` wildcard cert deployment**
- **Who:** PKI/Certificate Management Team
- **Timeline:** Within 72 hours
- Inventory all providers holding the wildcard cert, assess whether cert pinning is feasible for high-value subdomains, and evaluate replacing the shared wildcard with per-service certificates for origin servers.

**4. Investigate Incapsula WAF cluster anomalous port exposure (ports 21, 25)**
- **Who:** Network Security Team + Imperva account contact
- **Timeline:** Within 48 hours
- Confirm whether FTP (21) and SMTP (25) exposure is intentional proxy config or misconfiguration. If not required, request closure. Validate no open relay or anonymous FTP condition exists.

**5. Threat hunt `chemveric.com` and `360.leadershiplanding.com` co-hosted infrastructure**
- **Who:** Threat Intelligence / SOC Team
- **Timeline:** Within 72 hours
- Determine relationship of `chemveric.com` to SANS infrastructure (DNS misconfiguration vs. legitimate affiliate vs. domain-fronting abuse). Assess `360.leadershiplanding.com` security posture and cert sharing legitimacy.

**6. Implement continuous monitoring for `devlabs.sans.org` and non-CDN origins**
- **Who:** SOC / Detection Engineering
- **Timeline:** Within 1 week
- Onboard the three pivot queries below into automated Shodan Monitor alerts. Set alerting thresholds for new hosts appearing in the `devlabs` namespace or new CVEs fingerprinted against known origin IPs.

---

## Monitoring Queries

```
hostname:devlabs.sans.org port:80,443,8080,8443,9200,6443
```
*Continuous detection of newly exposed DevLabs nodes across management and API ports.*

```
ssl.cert.subject.cn:"*.sans.org" -org:"Amazon.com" -org:"Amazon Technologies" -org:"Akamai Technologies"
```
*Surfaces non-CDN hosts holding the SANS wildcard cert — catches new unprotected origins as they appear.*

```
org:"NTT DATA Services" ssl.cert.subject.cn:"sans.org" product:"Apache httpd"
```
*Monitors for additional Apache origin servers hosted by NTT DATA sharing SANS cert trust.*

```
hostname:sans.org vuln:CVE-2025-12141 OR vuln:CVE-2025-4123 OR vuln:CVE-2026-21720 OR vuln:CVE-2026-21721
```
*Tracks persistence or spread of the four confirmed CVEs across any `sans.org`-scoped host.*
```
ssl.cert.subject.cn:"360.leadershiplanding.com"
```
*Monitors the affiliate domain's infrastructure footprint for new or weakly protected nodes entering the SANS cert trust chain.*

# PDF Reports are from Kraken (Extra Content ) NOT Shodan
[Kraken Intelligence — https___dashboards.odin.devlabs.sans.org.pdf](https://github.com/user-attachments/files/28376036/Kraken.Intelligence.https___dashboards.odin.devlabs.sans.org.pdf)

[Kraken Intelligence — https___r2.odin.labs.sans.org[Rancher].pdf](https://github.com/user-attachments/files/28376273/Kraken.Intelligence.https___r2.odin.labs.sans.org.Rancher.pdf) {"Version":"v2.8.5","GitCommit":"7af1354e9","RancherPrime":"false"}
