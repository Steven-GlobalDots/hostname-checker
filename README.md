# Hostname Checker

## Overview
The Hostname Checker is a full-stack Cloudflare Worker application designed to analyze domain properties. It performs DNS lookups (A, CNAME, NS, CAA), checks for Cloudflare proxy status, verifying SSL issuance eligibility (Google, SSL.com, Let's Encrypt)

## Architecture
The application is built on **Cloudflare Workers** using the **Hono** framework.
- **Frontend**: Static HTML/CSS/JS served from the worker's assets.
- **Backend**: Worker API handling DNS (via DoH), Cloudflare API checks, and logic.
- **Database**: **Cloudflare D1** (`hosts_db`) stores checking history and results.
- **Services**:
    - `DNS Service`: resolves records using 1.1.1.1 DoH.
    - `Cloudflare Service`: validates Cloudflare IPs and uses the Cloudflare API for Zone Hold checks.

## Local Development
```bash
npm install
npx wrangler dev
```

## Deployment
```bash
npx wrangler deploy
```

## Live URL
https://hostname-check.super-cdn.com

## API Reference

### `POST /api/check-host`
Performs a check on a single hostname.

**Parameters**:
- `hostname` (string): The domain check.

**Response**:
```json
{
  "hostname": "example.com",
  "authoritative_ns": ["ns1.example.com"],
  "is_proxied": "yes",
  "dns_type": "A",
  "dns_result": "1.2.3.4",
  "ssl_google": "allowed",
  "ssl_ssl_com": "allowed",
  "ssl_lets_encrypt": "allowed",
  "zone_hold": "no",
  "updated_at": 1770123456789
}
```

### `GET /api/results`
Returns the history of checked hosts.

**Response**:
Array of host objects (same structure as above).

## Configuration
Required variables in `wrangler.jsonc`:
- `CLOUDFLARE_API_TOKEN`: API Token with `Zone:Custom Hostnames:Edit` permissions.
- `CLOUDFLARE_ZONE_ID`: Zone ID to use for testing custom hostnames (Zone Hold check).

D1 Database Binding:
- `hosts_db`

## Examples
```bash
curl -X POST "http://localhost:8787/api/check-host" \
     -H "Content-Type: application/json" \
     -d '{"hostname": "example.com"}'
```
