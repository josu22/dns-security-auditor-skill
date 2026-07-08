# Email Authentication Checklist (DNS-based)

Audit the DNS-published mail security posture: MX, SPF, DKIM, DMARC, MTA-STS,
TLS-RPT, DANE/TLSA, BIMI and CAA. These controls determine spoofing/phishing
resistance and mail deliverability.

## What to audit

- **MX** records and target providers.
- **SPF**: policy, `-all`/`~all`/`?all`/`+all`, authorized providers, the **10 DNS-lookup limit**, obsolete includes, SPF flattening (if used).
- **DKIM**: selectors, key length, rotation, per-provider DKIM.
- **DMARC**: policy (`p=`), alignment (adkim/aspf), `rua`/`ruf` reporting, aggregate/forensic reports, `pct`, subdomain policy `sp=`, enforcement.
- **MTA-STS** (`_mta-sts` TXT + `https://mta-sts.<domain>/.well-known/mta-sts.txt`).
- **TLS-RPT** (`_smtp._tls` TXT).
- **DANE/TLSA** (if applicable).
- **BIMI** (if applicable) + VMC.
- **CAA** for certificate issuance control.
- Shadow mail senders / third-party senders (Microsoft 365, Google Workspace, Proofpoint, Mimecast, SendGrid, Mailchimp, HubSpot, Salesforce, Brevo, Amazon SES, Zoho…).
- Spoofing / phishing risk; abuse of secondary domains.

## SPF rules

- Must **end in `-all`** (hardfail) or `~all` (softfail, transitional). `?all`/`+all` = effectively no protection.
- **≤ 10 DNS lookups** total (includes/a/mx/ptr/exists/redirect). Exceeding → `permerror` → SPF ignored.
- No obsolete/removed provider `include`s. No duplicate SPF TXT (multiple SPF records = `permerror`).
- Prefer flattening or provider consolidation over deep nested includes.

## DMARC rules

- A DMARC record must exist on every domain that sends (or claims to send) mail.
- Target enforcement: `p=quarantine` → `p=reject`. `p=none` is only acceptable as a **temporary, monitored** phase with a plan and a date.
- Set `rua=` (aggregate reports) to a monitored mailbox; `ruf=` optional (privacy-sensitive).
- Set `sp=` explicitly for subdomains; check alignment (`adkim`, `aspf` — `s` strict vs `r` relaxed).
- `pct<100` = partial enforcement; note it.
- **Parked/non-sending domains**: publish `v=spf1 -all` + `p=reject` + null MX (`. 0`) to prevent spoofing.

## DKIM rules

- Keys **≥ 1024-bit** (prefer 2048-bit). Flag 512/768-bit as weak.
- Rotate selectors periodically; retire old selectors.
- Each authorized sender should sign with its own selector and align with the domain.

## Transport / brand

- **MTA-STS** `enforce` mode + a valid policy file forces TLS on inbound SMTP.
- **TLS-RPT** provides visibility into TLS failures.
- **DANE/TLSA** requires DNSSEC; alternative/complement to MTA-STS.
- **BIMI** requires enforced DMARC (`quarantine`/`reject`) and (for most inboxes) a VMC.

## Suggested criticality

- **Crítico:** SPF allows any origin (`+all`) · DMARC absent on a critical mail domain · MX to an abandoned provider · subdomain takeover on a mail-used domain.
- **Alto:** DMARC `p=none` with no justification · DKIM absent · SPF with obsolete includes or `permerror`.
- **Medio:** CAA absent · MTA-STS absent · TLS-RPT absent · `pct<100` lingering.
- **Bajo:** TTL improvable · incomplete documentation.

## Safe commands

```bash
dig MX example.com
dig TXT example.com                        # SPF (v=spf1 ...)
dig TXT _dmarc.example.com                 # DMARC
dig TXT selector1._domainkey.example.com   # DKIM (guess common selectors)
dig TXT _mta-sts.example.com               # MTA-STS record
dig TXT _smtp._tls.example.com             # TLS-RPT
dig CAA example.com
# Common DKIM selectors to probe: default, google, selector1, selector2 (M365),
# k1 (Mailchimp/Mandrill), s1/s2, dkim, smtp, mail, ctct1/ctct2, everlytickey1
```
