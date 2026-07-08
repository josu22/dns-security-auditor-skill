# DNS Security Auditor — Agent Skill

> By **Josué López** ([@josu22](https://github.com/josu22)) · Cybersecurity — DNS, domain infrastructure, cloud & Microsoft 365 auditing.

A reusable **agent skill** that turns Claude (or any OpenAI-compatible agent)
into a **senior DNS security auditor**. It audits the DNS security posture of a
domain, subdomain set, DNS zone, tenant, or whole organization and produces a
**technical + executive report** with findings, evidence, severity, impact and a
**prioritized remediation plan**.

> Defensive validation only. Read-only checks, no exploitation, no resource
> claiming, no zone extraction. When information is missing, controls are marked
> *"No verificable con la información disponible"* with the exact evidence to request.

## What it covers

- **Governance & registrar** — inventory, ownership, expiry, MFA, registrar/registry lock, change control.
- **Authoritative architecture** — nameservers, anycast, redundancy, AXFR/TSIG, recursion, RRL, TTL/SOA, glue, lame delegation, IPv6/EDNS0/TCP.
- **DNSSEC** — chain of trust, DS/DNSKEY/RRSIG, NSEC/NSEC3, algorithms, rollover, expiration.
- **Email authentication** — SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA, BIMI, CAA.
- **Subdomain takeover** — dangling CNAMEs and cloud/SaaS re-claim risk with provider fingerprints.
- **Exposure & cloud/SaaS** — dev/staging/admin surfaces, Azure/AWS/GCP/M365 dependencies.
- **Internal recursive DNS, encrypted DNS (DoH/DoT), logging/monitoring, continuity** and **compliance mapping** (ISO 27001 / ENS / NIS2 / DORA / NIST SP 800-81).

## Repository layout

```
dns-security-auditor/
├── SKILL.md                              # main skill (persona, workflow, severity, rules)
├── agents/
│   └── openai.yaml                       # reusable system prompt for OpenAI-compatible runtimes
├── references/
│   ├── dns-security-checklist.md         # governance, registrar, architecture, records, exposure...
│   ├── dnssec-checklist.md               # full DNSSEC chain-of-trust review
│   ├── email-authentication-checklist.md # SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI/CAA
│   ├── subdomain-takeover-checklist.md   # dangling records & takeover fingerprints
│   └── report-template.md                # mandatory 14-section report structure
└── scripts/
    └── dns_passive_audit.py              # dependency-free passive DNS baseline (DoH)
```

## Install

### Claude Code / agent skills CLI

```bash
npx skills add josu22/dns-security-auditor-skill@dns-security-auditor
```

### Manual (Claude Code)

Copy the inner `dns-security-auditor/` folder into your skills directory:

```bash
# macOS/Linux
cp -r dns-security-auditor ~/.claude/skills/
# Windows (PowerShell)
Copy-Item -Recurse dns-security-auditor $env:USERPROFILE\.claude\skills\
```

Then ask your agent to *"audita la seguridad DNS de example.com"* and the skill triggers automatically.

### OpenAI-compatible runtimes

Load `dns-security-auditor/agents/openai.yaml` — its `instructions` field is a
drop-in system prompt for the Assistants/Responses API or any framework that
accepts a system prompt.

## Passive baseline script

Runs with **no third-party packages** (uses DNS-over-HTTPS via the Python
standard library). Python 3.8+.

```bash
python dns-security-auditor/scripts/dns_passive_audit.py example.com
python dns-security-auditor/scripts/dns_passive_audit.py example.com --subdomains subs.txt --json report.json
python dns-security-auditor/scripts/dns_passive_audit.py example.com --fingerprint   # HTTP-fingerprint dangling CNAMEs
python dns-security-auditor/scripts/dns_passive_audit.py example.com --dkim-selectors default,selector1,google
```

It reports records, SPF/DMARC/DKIM/CAA posture, DNSSEC presence, MTA-STS/TLS-RPT
and dangling-CNAME (subdomain-takeover) hints, ranked by severity, as human
output and optional JSON.

## Safety

Read-only by design. Zone transfer (AXFR) is documented only as a *controlled*
confirmatory check. Anything potentially intrusive requires prior authorization.
No offensive or destructive techniques.

## Author

**Josué López** — [@josu22](https://github.com/josu22)

Cybersecurity practitioner focused on DNS, domain infrastructure, cloud and
Microsoft 365 security auditing. Issues, ideas and contributions are welcome via
[GitHub issues](https://github.com/josu22/dns-security-auditor-skill/issues).

## License

MIT © 2026 Josué López — see [LICENSE](LICENSE).
