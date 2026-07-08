# DNS Security Checklist

Comprehensive control catalog for the DNS security audit. Walk every category.
For each control record: **result** (Conforme / No conforme / Parcial / No
verificable / No aplica), **evidence**, **risk**, **action**. DNSSEC has its own
file (`dnssec-checklist.md`); email has its own (`email-authentication-checklist.md`);
takeover has its own (`subdomain-takeover-checklist.md`).

---

## A. Governance, inventory and domain ownership

Review:
- Full inventory of domains and subdomains.
- Main, defensive, historical, abandoned and redirected domains.
- Legal ownership of the domain; current registrar; expiry dates; auto-renew.
- Administrative, technical and abuse contacts.
- WHOIS/RDAP usage; registrant privacy.
- Procedures for domain add / remove / modify.
- Internal domain owner; RACI matrix; change control.
- Periodic DNS record review.
- Emergency procedure for DNS compromise.
- DNS provider management; contracts and SLA; segregation of duties.
- Evidence of approval for critical changes.
- Existence of forgotten, parked or unmonitored domains.

Detect:
- Domain near expiry · domain managed by ex-employees · stale contacts ·
  no inventory · critical domains with no owner · secondary domains used by
  shadow IT · look-alike domains exposed to typosquatting · over-dependence on a
  single provider.

## B. Registrar security

Review:
- MFA mandatory on all accounts; phishing-resistant MFA where possible
  (passkeys / FIDO2 / hardware keys); remove SMS as primary factor.
- Users with registrar access; roles & permissions; shared accounts; third-party access.
- Audit log; change alerts.
- Transfer lock; **registrar lock**; **registry lock** for critical domains.
- Protection against nameserver changes; against DS-record changes; against unauthorized transfer.
- IP restrictions if available.
- Account recovery; out-of-band verification procedure.
- Protection of the email account tied to the registrar.
- Expiry & auto-renew; protected billing; change history.

Detect:
- No MFA · shared accounts · use of personal mailboxes · no registry lock ·
  nameserver changes without dual approval · weak account recovery · low-trust
  registrar for critical domains.

## C. Authoritative DNS architecture

Review:
- Authoritative DNS provider; nameservers in the parent zone; number of NS; geo distribution; anycast.
- Primary/secondary separation; multi-region and multi-provider redundancy.
- Primary server exposure; AXFR/IXFR; zone transfers; **TSIG** for transfers; authorized-IP restriction.
- Recursion disabled on public authoritative servers; version disclosure; CHAOS TXT records.
- Rate limiting / DNS RRL; DDoS protection.
- Coherent TTLs; correct SOA & serial; refresh/retry/expire/minimum TTL.
- Glue records; lame delegation; inconsistent delegations; non-responding nameservers.
- Parent vs child zone differences; inconsistent answers across nameservers.
- IPv4 & IPv6; UDP fragmentation; EDNS0; TCP/53; DNS-over-TCP functional.
- DNSSEC on authoritative (see dnssec-checklist.md).

Detect:
- Open zone transfer · open recursion · inconsistent nameservers · no HA ·
  broken DNSSEC · orphan DS · expired signatures · obsolete algorithms · lame
  delegation · primary-server exposure · no DDoS protection.

## E. Public DNS records

Review every relevant record: A, AAAA, CNAME, MX, TXT, SPF, DKIM, DMARC, NS,
SOA, SRV, CAA, PTR, TLSA, SSHFP, NAPTR, DS, DNSKEY, RRSIG, BIMI, MTA-STS,
TLS-RPT, ACME-challenge, SaaS verification records.

Detect:
- Legacy provider records · wildcard records · internal records published by
  mistake · records with private IPs · records with sensitive names · leftover
  temporary records · duplicate records · chained CNAMEs · CNAME to external
  domains · CNAME to non-existent resources · orphan subdomains · **subdomain
  takeover** (see dedicated file) · TXT records with secrets/tokens/sensitive
  info · overly permissive SPF · SPF with too many lookups · SPF with obsolete
  includes · MX pointing to unused providers · weak/absent DKIM · absent DMARC or
  `p=none` with no plan · absent/permissive CAA · inconsistent PTR · TTL too low
  or too high for context.

## G. Subdomains and external exposure

Review:
- Subdomain enumeration; active vs historical subdomains.
- Subdomains with external CNAMEs; subdomains pointing to deleted cloud services (takeover).
- Wildcard DNS.
- Environments: dev, test, pre, staging, qa, uat.
- Admin panels, VPN, Citrix, RDP gateways, OWA, Autodiscover, MDM, SSO, IdP, APIs, buckets, CDN, WAF, load balancers.
- Orphan IPs; CT-log certificates; leaked internal names; exposed technologies; associated ports.
- Relationship between DNS and attack surface.

Dangerous name patterns to flag: `admin`, `internal`, `intranet`, `vpn`,
`backup`, `old`, `legacy`, `dev`, `test`, `pre`, `staging`, `jira`,
`confluence`, `gitlab`, `grafana`, `kibana`, `zabbix`, `prometheus`, `elastic`,
`sonarqube`, `jenkins`, `citrix`, `rdp`, `firewall`, `router`, `nas`, `s3`,
`blob`, `storage`, `sharepoint`, `autodiscover`.

## H. Cloud & SaaS risk

Review records related to: Azure DNS, Microsoft 365, Entra ID, SharePoint,
Exchange Online, Teams, Intune; AWS Route 53, CloudFront, S3, ELB/ALB, API
Gateway; Google Cloud DNS, Cloud Run, App Engine, Firebase; Cloudflare, Fastly,
Akamai, Vercel, Netlify, GitHub Pages, Heroku, Shopify, Zendesk, Atlassian,
HubSpot, Salesforce, SendGrid, Mailchimp, Brevo, Stripe, Webflow.

Controls:
- CNAME to non-existent resources; old SaaS validations; forgotten TXT tokens;
  ownership verification; takeover risk; records enabling service takeover;
  critical dependencies; providers with no internal owner; missing secure SaaS
  offboarding; missing periodic review.

## I. Internal recursive DNS (when internal info is available)

Review: recursive servers; forwarders; root hints; conditional forwarders;
split-horizon DNS; restricted recursion; open resolver; ACL by network;
segmentation; internal vs external DNS; Active Directory integration; secure
dynamic updates; dynamic DNS; aging/scavenging; AD-integrated zones; replication;
delegated administration; zone permissions; logging; query logging; response
policy zones (RPZ); DNS firewall; protective DNS; sinkholing; malicious-domain
blocking; EDR/SIEM/SOAR integration; DGA / tunneling / exfiltration detection;
unauthorized DoH/DoT; control of external resolvers; endpoint policies; DNS leak;
DNS over VPN; DNS on guest networks; DNS for OT/IoT.

## J. Encrypted DNS (DoH/DoT) and privacy

Review: permitted DoH/DoT usage; corporate policy; blocking of unauthorized
resolvers; browser configuration (Windows, macOS, Linux, Android, iOS) via
MDM/Intune/GPO; Firefox TRR, Chrome Secure DNS, Edge Secure DNS; risk of
bypassing DNS controls; loss of visibility; authorized protective DNS; logs &
privacy; legal compliance; VPN split tunneling; teleworking resolution.

## K. Logs, monitoring and detection

Review: DNS change logs; query/response logs; registrar logs; provider logs;
zone-transfer logs; DNSSEC error logs; nameserver-change logs.
Alerts for: critical record modification, MX change, NS change, DS/DNSKEY change,
domain expiry, DNSSEC expiry, subdomain takeover, look-alike domains.
Detection: SIEM integration; SOC use cases; DNS tunneling; DGA; fast flux;
anomalous NXDOMAIN; beaconing; queries to newly-registered domains; external
resolvers. Log retention; log protection; periodic review.

## L. Continuity, resilience and response

Review: DNS continuity plan; RTO/RPO; zone backups; periodic exports; tested
restore; rollback procedure; emergency-change procedure; 24/7 provider contacts;
SLA; DDoS protection; anycast; multi-provider DNS; secondary DNS.
Runbooks for: domain hijack, DNSSEC failure, malicious MX change, subdomain
takeover, accidental expiry. Drills; evidence of tests.

## M. Compliance and normative mapping

Map findings, where possible, to: ISO/IEC 27001:2022, ENS, NIS2, DORA, CIS
Controls, NIST CSF, NIST SP 800-81 Rev. 3, ICANN/IETF good practices, and the
client's internal policies. Never force a mapping without sufficient evidence.
