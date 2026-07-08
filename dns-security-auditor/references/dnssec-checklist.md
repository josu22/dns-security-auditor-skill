# DNSSEC Checklist

Review the full DNSSEC posture and chain of trust. DNSSEC provides integrity and
authenticity of DNS answers; a **broken** chain is worse than none (SERVFAIL /
outage), so weigh operational risk alongside security.

## What to review

- Whether the zone is **signed**.
- Whether there is a **complete chain of trust from the root**.
- **DS** record present in the parent (and matching the child DNSKEY).
- **DNSKEY** set; **RRSIG** on records; **NSEC** or **NSEC3**.
- Algorithms in use; key length.
- State of **KSK** and **ZSK**; key rotation; automated rollover.
- Signature validity / expiration windows.
- Correct validation from external resolvers (`dig +dnssec`, validating resolver).
- SERVFAIL errors caused by DNSSEC.
- Consistency across all nameservers.
- Registrar support for publishing DS.
- Documented key-change procedure.
- Emergency plan for a broken DNSSEC chain.
- Use of **CDS/CDNSKEY** if applicable (automated DS maintenance).
- **Zone-walking** risk with NSEC (enumeration).
- Operational risk of misconfigured NSEC3 (iterations/opt-out).
- Compatibility with external providers and services.

## Classification

- **Correcto:** valid chain, current signatures, acceptable algorithms, documented operation.
- **Parcial:** zone signed but with operational weaknesses (e.g. no rollover automation, NSEC zone-walking, short signature windows).
- **Crítico:** DNSSEC broken — incorrect DS, expired signatures, or failed validation → SERVFAIL / outage / trust failure on a critical domain.
- **No implementado:** DNSSEC absent — rate criticality by domain type (critical/corporate vs marketing/parked).

## Algorithm guidance

- **Prefer:** ECDSA P-256 (alg 13) or ED25519 (alg 15) — modern, short keys, fast validation.
- **Acceptable:** RSASHA256 (alg 8) with ≥2048-bit keys.
- **Avoid / flag:** RSASHA1 (alg 5/7), RSAMD5, DSA, SHA-1 DS digests — obsolete/weak.
- **NSEC3:** low iterations (0 recommended per RFC 9276), appropriate salt; avoid high iteration counts (DoS on validators).

## Common findings

| Finding | Severity (typical) |
|---|---|
| Expired RRSIG on a critical zone (SERVFAIL) | Crítico |
| DS in parent but zone unsigned / DNSKEY missing (orphan DS) | Crítico |
| DS digest/key mismatch → validation failure | Crítico |
| Obsolete algorithm (RSASHA1) | Alto |
| No rollover automation, manual keys near expiry | Alto |
| NSEC zone-walking enables full enumeration | Medio |
| NSEC3 with excessive iterations | Medio |
| DNSSEC not implemented on a critical/corporate domain | Alto–Medio (by context) |
| DNSSEC not implemented on parked/marketing domain | Bajo–Informativo |

## Safe validation commands

```bash
dig +dnssec example.com            # RRSIG present in answer?
dig DNSKEY example.com +multi      # zone keys (KSK/ZSK flags 257/256)
dig DS example.com                 # DS in parent
dig +dnssec +cd example.com        # bypass validation to compare
delv example.com                   # bind's validating lookup (if available)
# External validators (manual): dnsviz.net, dnssec-debugger (Verisign)
```

Flag as **No verificable** anything requiring registrar/provider console access
(rollover automation, key custody, emergency procedure) and list the evidence to request.
