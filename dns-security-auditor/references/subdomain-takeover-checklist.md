# Subdomain Takeover Checklist

Subdomain takeover happens when a DNS record (usually a CNAME, sometimes A/NS)
points to a de-provisioned third-party resource that an attacker can re-claim,
letting them serve content, phish, or capture cookies on your subdomain.

## Detection workflow

1. **Enumerate** subdomains (CT logs / crt.sh, passive sources, provided lists).
2. **Resolve** each: follow CNAME chains to the final target.
3. **Classify** each record:
   - CNAME → external SaaS/cloud hostname.
   - A/AAAA → cloud IP that may be released.
   - NS → delegated to a zone that may be unclaimed.
4. **Check the target's liveness**: does the pointed-to resource still exist?
   - `NXDOMAIN` on the CNAME target, or
   - HTTP/HTTPS returns a provider "no such app / bucket not found / 404 fingerprint", or
   - TLS/service errors typical of an unclaimed resource.
5. **Match the fingerprint** to a known-takeoverable provider (below).
6. **Validate safely** (see rules) — do **not** actually claim the resource.

## Dangling-record signals

- CNAME to a resource that returns `NXDOMAIN`.
- CNAME/A to a cloud endpoint showing the provider's "unclaimed / not found" page.
- Old SaaS **verification TXT** left after offboarding.
- Wildcard masking dead subdomains.
- A/AAAA to an elastic IP or cloud IP no longer owned.
- NS delegation to a nameserver/zone not configured.

## Commonly takeoverable providers (fingerprint hints)

| Provider | Typical CNAME target | Fingerprint hint |
|---|---|---|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| AWS S3 | `*.s3*.amazonaws.com` | "NoSuchBucket" |
| AWS CloudFront | `*.cloudfront.net` | 403 / "Bad request" when distribution deleted |
| Azure (App Service / Traffic Mgr / Blob / CDN) | `*.azurewebsites.net`, `*.trafficmanager.net`, `*.blob.core.windows.net`, `*.azureedge.net` | NXDOMAIN / "404 Web Site not found" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Vercel | `*.vercel.app` | "The deployment could not be found" (404) |
| Netlify | `*.netlify.app` | "Not Found" Netlify page |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Cargo/Unbounce/Surge/Webflow/Tumblr/Ghost/Helpscout/Statuspage | vendor host | vendor-specific "not found" page |

(Use this as a *hint* list; always confirm the live fingerprint — providers
change behavior and patch takeover vectors.)

## Cloud/SaaS specifics

- **Azure**: dangling CNAMEs to deleted App Services / Traffic Manager / Blob /
  CDN endpoints are re-registrable by name → high takeover risk. Cross-check
  against tenant resources when you have access.
- **AWS**: released Elastic IPs and deleted S3 buckets (same global name) are
  classic vectors.
- **M365/SaaS**: leftover `MS=`, `google-site-verification`, or vendor TXT after
  offboarding can allow re-verification of ownership by a third party.

## Safe validation rules

- Confirm via **DNS resolution + passive HTTP fingerprint** only.
- **Do not** register, claim, or take over the resource — that is intrusive.
- If proof-of-exploitability is requested, **request written authorization**
  first and, if granted, claim only with the client's own account.
- Report: subdomain, record type, target, fingerprint evidence, provider,
  probability, impact, and the exact remediation (remove/repoint the record, or
  re-claim the resource under a controlled account).

## Severity

- **Crítico:** takeover-able subdomain used for auth, mail, SSO, payments, or a primary brand host.
- **Alto:** takeover-able subdomain on a marketing/app host (cookie theft, phishing, brand abuse).
- **Medio:** dangling record with no current takeover path but at risk if the target is released.
- **Bajo/Informativo:** stale verification TXT with no takeover path.

## Safe commands

```bash
dig CNAME sub.example.com
dig sub.example.com +noall +answer      # follow the chain
curl -sI https://sub.example.com        # read fingerprint headers/status (no auth, no writes)
# Enumeration: crt.sh (CT logs), passive DNS; avoid brute-force against prod without authorization.
```
