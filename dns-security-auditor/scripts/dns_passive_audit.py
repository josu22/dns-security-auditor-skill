#!/usr/bin/env python3
"""
dns_passive_audit.py — Passive, non-intrusive DNS security baseline.

Gathers public DNS evidence for the DNS Security Auditor skill: records,
SPF/DMARC/DKIM/CAA posture, DNSSEC presence, MTA-STS/TLS-RPT, and dangling-CNAME
(subdomain-takeover) hints. Uses DNS-over-HTTPS (Google + Cloudflare JSON API)
so it needs NO third-party packages — only the Python standard library.

This is DEFENSIVE VALIDATION ONLY. It performs read-only DNS lookups and, when
--fingerprint is set, harmless HTTP HEAD requests to read provider "not found"
pages. It never claims resources, never brute-forces, never transfers zones.

Author:  Josué López (@josu22) — https://github.com/josu22/dns-security-auditor-skill
License: MIT (c) 2026 Josué López

Usage:
  python dns_passive_audit.py example.com
  python dns_passive_audit.py example.com --subdomains subs.txt --json out.json
  python dns_passive_audit.py example.com --fingerprint      # HTTP fingerprint dangling CNAMEs
  python dns_passive_audit.py example.com --dkim-selectors default,selector1,google

Exit code is always 0 unless arguments are invalid; findings are in the report.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.parse
import urllib.error

# ---- DNS-over-HTTPS resolvers (JSON API) -----------------------------------

DOH_ENDPOINTS = [
    ("google", "https://dns.google/resolve"),
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
]

TYPE_NUM = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
    "AAAA": 28, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "CAA": 257,
}

# Known takeover-prone target suffixes -> provider (hint list; always confirm live).
TAKEOVER_SUFFIXES = {
    ".github.io": "GitHub Pages",
    ".s3.amazonaws.com": "AWS S3",
    ".s3-website": "AWS S3 website",
    ".cloudfront.net": "AWS CloudFront",
    ".azurewebsites.net": "Azure App Service",
    ".trafficmanager.net": "Azure Traffic Manager",
    ".blob.core.windows.net": "Azure Blob",
    ".azureedge.net": "Azure CDN",
    ".cloudapp.azure.com": "Azure Cloud",
    ".herokuapp.com": "Heroku",
    ".herokudns.com": "Heroku",
    ".vercel.app": "Vercel",
    ".netlify.app": "Netlify",
    ".myshopify.com": "Shopify",
    ".fastly.net": "Fastly",
    ".zendesk.com": "Zendesk",
    ".github.io.": "GitHub Pages",
    ".ghost.io": "Ghost",
    ".surge.sh": "Surge",
    ".bitbucket.io": "Bitbucket",
    ".wpengine.com": "WP Engine",
    ".pantheonsite.io": "Pantheon",
    ".readthedocs.io": "Read the Docs",
    ".statuspage.io": "Statuspage",
}

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "dkim", "smtp", "mail", "mandrill", "everlytickey1", "ctct1", "ctct2",
    "mte1", "protonmail", "protonmail2", "zoho", "amazonses",
]

USER_AGENT = "dns-security-auditor/1.0 (+passive-defensive-audit)"


def doh_query(name: str, rtype: str, timeout: float = 6.0) -> dict:
    """Resolve name/rtype over DoH; returns parsed JSON or {'_error': ...}."""
    qtype = TYPE_NUM.get(rtype.upper(), rtype)
    last_err = None
    for provider, base in DOH_ENDPOINTS:
        params = urllib.parse.urlencode({"name": name, "type": qtype})
        url = f"{base}?{params}"
        req = urllib.request.Request(url, headers={
            "accept": "application/dns-json",
            "user-agent": USER_AGENT,
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                data["_provider"] = provider
                return data
        except Exception as e:  # noqa: BLE001 - report, do not crash the audit
            last_err = f"{provider}: {e}"
            continue
    return {"_error": last_err or "no resolver reachable"}


def answers(resp: dict, rtype: str) -> list[str]:
    """Extract answer 'data' strings for the given record type."""
    if not resp or "Answer" not in resp:
        return []
    want = TYPE_NUM.get(rtype.upper())
    out = []
    for a in resp["Answer"]:
        if want is None or a.get("type") == want:
            out.append(a.get("data", "").strip())
    return out


def txt_join(values: list[str]) -> list[str]:
    """DoH returns TXT with surrounding quotes and split strings; normalize."""
    cleaned = []
    for v in values:
        v = v.strip()
        if v.startswith('"') and v.endswith('"'):
            # collapse quoted chunks: "a" "b" -> ab
            parts = [p for p in v.split('"') if p not in ("", " ")]
            v = "".join(parts)
        cleaned.append(v)
    return cleaned


def add(findings: list, sev: str, category: str, title: str, evidence: str, rec: str):
    findings.append({
        "severity": sev, "category": category, "finding": title,
        "evidence": evidence, "recommendation": rec,
    })


# ---- Individual checks ------------------------------------------------------

def check_dnssec(domain: str, findings: list) -> dict:
    ds = answers(doh_query(domain, "DS"), "DS")
    dnskey = answers(doh_query(domain, "DNSKEY"), "DNSKEY")
    # AD flag from a validating resolver = chain validated
    ad = doh_query(domain, "A").get("AD", False)
    state = "no-implementado"
    if ds and dnskey:
        state = "firmado"
    elif ds and not dnskey:
        state = "roto-ds-huerfano"
        add(findings, "Crítico", "DNSSEC",
            "DS presente en el parent pero sin DNSKEY en la zona (orphan DS)",
            f"DS={ds}; DNSKEY vacío", "Publicar DNSKEY válido o eliminar el DS del parent; validar la cadena.")
    elif dnskey and not ds:
        state = "firmado-sin-ds"
        add(findings, "Alto", "DNSSEC",
            "Zona con DNSKEY pero sin DS en el parent (cadena de confianza incompleta)",
            f"DNSKEY={len(dnskey)} claves; DS vacío", "Publicar el DS en el registrar para cerrar la cadena desde root.")
    else:
        add(findings, "Medio", "DNSSEC",
            "DNSSEC no implementado",
            "Sin DS ni DNSKEY", "Evaluar firmar la zona (criticidad según tipo de dominio); preferir ECDSA P-256 o ED25519.")
    return {"state": state, "ds": ds, "dnskey_count": len(dnskey), "ad_flag": bool(ad)}


def check_spf(domain: str, findings: list) -> dict:
    txt = txt_join(answers(doh_query(domain, "TXT"), "TXT"))
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    info = {"records": spf}
    if not spf:
        add(findings, "Alto", "Correo/SPF", "SPF ausente",
            "Sin registro v=spf1", "Publicar SPF terminando en -all con los emisores autorizados.")
        return info
    if len(spf) > 1:
        add(findings, "Crítico", "Correo/SPF", "Múltiples registros SPF (permerror)",
            f"{len(spf)} registros v=spf1", "Consolidar en un único registro SPF.")
    rec = spf[0]
    lookups = sum(rec.lower().count(m) for m in ("include:", "a:", "mx", "ptr", "exists:", "redirect="))
    info["approx_lookups"] = lookups
    if lookups > 10:
        add(findings, "Alto", "Correo/SPF", "SPF supera ~10 lookups DNS (permerror probable)",
            f"~{lookups} mecanismos con lookup", "Reducir includes / aplicar SPF flattening.")
    tail = rec.lower().split()[-1] if rec.split() else ""
    if tail.endswith("+all") or "+all" in rec.lower():
        add(findings, "Crítico", "Correo/SPF", "SPF permite cualquier origen (+all)",
            rec, "Cambiar a -all (hardfail).")
    elif "?all" in rec.lower():
        add(findings, "Alto", "Correo/SPF", "SPF neutral (?all) — sin protección efectiva",
            rec, "Cambiar a -all.")
    elif "~all" in rec.lower():
        add(findings, "Medio", "Correo/SPF", "SPF en softfail (~all)",
            rec, "Migrar a -all tras validar entregabilidad.")
    return info


def check_dmarc(domain: str, findings: list) -> dict:
    txt = txt_join(answers(doh_query(f"_dmarc.{domain}", "TXT"), "TXT"))
    dmarc = [t for t in txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        add(findings, "Crítico", "Correo/DMARC", "DMARC ausente",
            "Sin registro en _dmarc", "Publicar DMARC; iniciar en p=none monitorizado y escalar a p=reject.")
        return {"record": None}
    rec = dmarc[0].lower()
    policy = "none"
    for tok in rec.split(";"):
        tok = tok.strip()
        if tok.startswith("p="):
            policy = tok[2:].strip()
    has_rua = "rua=" in rec
    if policy == "none":
        add(findings, "Alto", "Correo/DMARC", "DMARC en p=none (sin enforcement)",
            dmarc[0], "Escalar a quarantine y luego reject tras revisar informes rua.")
    if not has_rua:
        add(findings, "Medio", "Correo/DMARC", "DMARC sin dirección de informes agregados (rua)",
            dmarc[0], "Añadir rua= a un buzón monitorizado para tener visibilidad.")
    return {"record": dmarc[0], "policy": policy, "rua": has_rua}


def check_caa(domain: str, findings: list) -> dict:
    caa = answers(doh_query(domain, "CAA"), "CAA")
    if not caa:
        add(findings, "Medio", "Certificados/CAA", "CAA ausente",
            "Sin registros CAA", "Publicar CAA restringiendo las CAs autorizadas (issue/issuewild + iodef).")
    return {"records": caa}


def check_mx_mailhardening(domain: str, findings: list) -> dict:
    mx = answers(doh_query(domain, "MX"), "MX")
    mta = txt_join(answers(doh_query(f"_mta-sts.{domain}", "TXT"), "TXT"))
    tlsrpt = txt_join(answers(doh_query(f"_smtp._tls.{domain}", "TXT"), "TXT"))
    if mx:
        if not any(t.lower().startswith("v=stsv1") for t in mta):
            add(findings, "Medio", "Correo/MTA-STS", "MTA-STS ausente",
                "Sin _mta-sts", "Publicar MTA-STS en modo enforce + fichero de política.")
        if not any(t.lower().startswith("v=tlsrptv1") for t in tlsrpt):
            add(findings, "Medio", "Correo/TLS-RPT", "TLS-RPT ausente",
                "Sin _smtp._tls", "Publicar TLS-RPT para visibilidad de fallos TLS.")
    else:
        # Non-sending domain should be locked down.
        add(findings, "Bajo", "Correo", "Dominio sin MX",
            "Sin registros MX", "Si no envía/recibe correo, publicar null MX (. 0) + SPF -all + DMARC p=reject.")
    return {"mx": mx, "mta_sts": mta, "tls_rpt": tlsrpt}


def check_dkim(domain: str, selectors: list[str], findings: list) -> dict:
    found = {}
    for sel in selectors:
        txt = txt_join(answers(doh_query(f"{sel}._domainkey.{domain}", "TXT"), "TXT"))
        dk = [t for t in txt if "v=dkim1" in t.lower() or "p=" in t.lower()]
        if dk:
            found[sel] = dk[0][:120]
    if not found:
        add(findings, "Alto", "Correo/DKIM",
            "No se encontró DKIM en los selectores comunes probados",
            f"Selectores probados: {', '.join(selectors)}",
            "Verificar el selector real del proveedor; publicar DKIM (≥2048 bits) y firmar el correo saliente.")
    return {"selectors_found": found}


def check_ns_consistency(domain: str, findings: list) -> dict:
    ns = sorted(answers(doh_query(domain, "NS"), "NS"))
    if len(ns) < 2:
        add(findings, "Alto", "Arquitectura", "Menos de 2 nameservers (sin alta disponibilidad)",
            f"NS={ns}", "Configurar ≥2 nameservers, idealmente anycast y multi-región/proveedor.")
    return {"ns": ns}


def check_subdomains(domain: str, subs: list[str], fingerprint: bool, findings: list) -> list:
    results = []
    for sub in subs:
        fqdn = sub if sub.endswith(domain) else f"{sub}.{domain}"
        resp = doh_query(fqdn, "CNAME")
        cname = answers(resp, "CNAME")
        entry = {"subdomain": fqdn, "cname": cname, "status": "ok"}
        if cname:
            target = cname[0].rstrip(".")
            provider = None
            for suffix, prov in TAKEOVER_SUFFIXES.items():
                if suffix.strip(".") in target:
                    provider = prov
                    break
            # Does the CNAME target resolve at all?
            tgt_a = doh_query(target, "A")
            nx = tgt_a.get("Status") == 3  # NXDOMAIN
            entry["target"] = target
            entry["target_provider"] = provider
            entry["target_nxdomain"] = nx
            if nx and provider:
                entry["status"] = "posible-takeover"
                add(findings, "Crítico", "Subdomain Takeover",
                    f"CNAME colgante hacia {provider} con target NXDOMAIN",
                    f"{fqdn} -> {target} (NXDOMAIN); proveedor {provider}",
                    "Eliminar/repuntar el registro o reclamar el recurso desde la cuenta propia. NO reclamar el recurso ajeno.")
            elif nx:
                entry["status"] = "cname-colgante"
                add(findings, "Alto", "Subdomain Takeover",
                    "CNAME apunta a un target que no resuelve (NXDOMAIN)",
                    f"{fqdn} -> {target} (NXDOMAIN)",
                    "Revisar y eliminar el registro colgante; confirmar si el recurso es reclamable.")
            elif provider and fingerprint:
                fp = _http_fingerprint(fqdn)
                entry["http_fingerprint"] = fp
        results.append(entry)
    return results


def _http_fingerprint(host: str, timeout: float = 6.0) -> str:
    """Harmless HEAD/GET to read a provider 'not found' page. Read-only."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/",
                                         headers={"user-agent": USER_AGENT}, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(2048).decode("utf-8", "ignore")
                return f"{r.status} {body[:160].strip()}"
        except urllib.error.HTTPError as e:
            try:
                body = e.read(2048).decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                body = ""
            return f"{e.code} {body[:160].strip()}"
        except Exception as e:  # noqa: BLE001
            last = str(e)
    return f"unreachable: {last}"


# ---- Orchestration ---------------------------------------------------------

def audit(domain: str, subs: list[str], selectors: list[str], fingerprint: bool) -> dict:
    findings: list = []
    report = {
        "domain": domain,
        "records": {
            "A": answers(doh_query(domain, "A"), "A"),
            "AAAA": answers(doh_query(domain, "AAAA"), "AAAA"),
            "SOA": answers(doh_query(domain, "SOA"), "SOA"),
        },
        "ns": check_ns_consistency(domain, findings),
        "dnssec": check_dnssec(domain, findings),
        "spf": check_spf(domain, findings),
        "dmarc": check_dmarc(domain, findings),
        "dkim": check_dkim(domain, selectors, findings),
        "caa": check_caa(domain, findings),
        "mail": check_mx_mailhardening(domain, findings),
    }
    if subs:
        report["subdomains"] = check_subdomains(domain, subs, fingerprint, findings)
    order = {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3, "Informativo": 4}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    report["findings"] = findings
    report["summary"] = {
        "total": len(findings),
        "por_severidad": {s: sum(1 for f in findings if f["severity"] == s)
                          for s in ("Crítico", "Alto", "Medio", "Bajo", "Informativo")},
    }
    return report


def print_human(r: dict) -> None:
    s = r["summary"]
    print(f"\n=== Auditoría DNS pasiva: {r['domain']} ===")
    print(f"NS: {', '.join(r['ns']['ns']) or '—'}")
    print(f"DNSSEC: {r['dnssec']['state']} (AD flag: {r['dnssec']['ad_flag']})")
    print(f"MX: {', '.join(r['mail']['mx']) or '—'}")
    print(f"SPF: {r['spf'].get('records') or '—'}")
    print(f"DMARC: {r['dmarc'].get('policy') or 'ausente'}")
    print(f"DKIM selectores hallados: {list(r['dkim']['selectors_found'].keys()) or '—'}")
    print(f"CAA: {r['caa']['records'] or '—'}")
    print(f"\nHallazgos: {s['total']}  "
          + "  ".join(f"{k}:{v}" for k, v in s["por_severidad"].items() if v))
    for f in r["findings"]:
        print(f"  [{f['severity']:>10}] {f['category']}: {f['finding']}")
        print(f"               evidencia: {f['evidence']}")
    print("\nRecuerda: baseline pasivo. Contrasta con evidencia interna (registrar, "
          "zona, logs, cloud) y marca lo no verificable. No sustituye el informe completo.")


def main() -> int:
    # Windows consoles default to cp1252; force UTF-8 so accents/em-dashes render.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - older Pythons / non-reconfigurable streams
            pass
    p = argparse.ArgumentParser(description="Passive DNS security baseline (defensive, read-only).")
    p.add_argument("domain", help="Domain to audit, e.g. example.com")
    p.add_argument("--subdomains", help="File with one subdomain per line (label or FQDN).")
    p.add_argument("--dkim-selectors", help="Comma-separated DKIM selectors to probe.")
    p.add_argument("--fingerprint", action="store_true",
                   help="HTTP-fingerprint dangling CNAMEs (read-only GET).")
    p.add_argument("--json", help="Write full JSON report to this path.")
    args = p.parse_args()

    subs = []
    if args.subdomains:
        try:
            with open(args.subdomains, "r", encoding="utf-8") as fh:
                subs = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print(f"No se pudo leer --subdomains: {e}", file=sys.stderr)
            return 2

    selectors = COMMON_DKIM_SELECTORS
    if args.dkim_selectors:
        selectors = [s.strip() for s in args.dkim_selectors.split(",") if s.strip()]

    report = audit(args.domain.strip().rstrip("."), subs, selectors, args.fingerprint)
    print_human(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"\nJSON escrito en: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
