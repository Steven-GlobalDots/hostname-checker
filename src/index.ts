import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { dnsQuery, RecordType, getAuthoritativeNS, parseCAA, DnsResponse } from './lib/dns';
import { isCloudflareIp, checkZoneHold, ZoneHoldResult } from './lib/cloudflare';

type Bindings = {
  hosts_db: D1Database;
  CLOUDFLARE_API_TOKEN: string;
  CLOUDFLARE_ZONE_ID: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.use('/api/*', cors());

// Helper to analyze CAA
function checkCaaPermission(caaRecords: any[], domain: string): 'allowed' | 'not_allowed' {
  if (!caaRecords || caaRecords.length === 0) return 'allowed'; // No records = all allowed

  // Check if any record allows the domain
  const allowed = caaRecords.some(r => {
    if (r.tag !== 'issue' && r.tag !== 'issuewild') return false;
    // Simple check: does value contain the domain?
    return r.value.includes(domain);
  });

  return allowed ? 'allowed' : 'not_allowed';
}

app.post('/api/check-host', async (c) => {
  const body = await c.req.json();
  const hostname = body.hostname?.trim();

  if (!hostname) {
    return c.json({ error: 'Hostname check failed' }, 400);
  }

  try {
    // 1. DNS Lookup (A Record)
    const aRecord = await dnsQuery(hostname, RecordType.A);
    const dnsType = 'A'; // Presumed
    let dnsResult = '';
    let isProxied = 'no';

    // Check A records
    if (aRecord.Answer && aRecord.Answer.length > 0) {
      const ips = aRecord.Answer.filter(a => a.type === 1).map(a => a.data);
      dnsResult = ips.join(', ');
      // Check if any IP is Cloudflare
      if (ips.some(ip => isCloudflareIp(ip))) {
        isProxied = 'yes';
      }
    }

    // If no A records, check CNAME?
    // Actually, dnsQuery for A follows CNAMEs usually, but let's check explicit CNAME if needed.
    // If A record query returned CNAMEs in Answer, we use that.

    // 2. Authoritative NS
    // We need to look up NS for the domain (SLD), not necessarily the subdomain.
    // Simplified: Lookup NS for the hostname. If empty, try parent.
    let nsRecord = await dnsQuery(hostname, RecordType.NS);
    let authNs = getAuthoritativeNS(nsRecord);
    if (authNs.length === 0) {
      // Try parent domain logic (dumb implementation: strip first part)
      const parent = hostname.split('.').slice(1).join('.');
      if (parent) {
        nsRecord = await dnsQuery(parent, RecordType.NS);
        authNs = getAuthoritativeNS(nsRecord);
      }
    }

    // 3. CAA Check
    // Try hostname, then parent, etc.
    let caaRes = await dnsQuery(hostname, RecordType.CAA);
    let caaAnswers = caaRes.Answer || [];
    if (caaAnswers.length === 0) {
      const parent = hostname.split('.').slice(1).join('.');
      if (parent) {
        caaRes = await dnsQuery(parent, RecordType.CAA);
        caaAnswers = caaRes.Answer || [];
      }
    }

    const parsedCaas = caaAnswers.map(parseCAA).filter(x => x !== null);

    const sslGoogle = checkCaaPermission(parsedCaas, 'pki.goog');
    const sslSslCom = checkCaaPermission(parsedCaas, 'ssl.com');
    const sslLetsEncrypt = checkCaaPermission(parsedCaas, 'letsencrypt.org');

    // 4. Zone Hold
    // Uses Env vars
    const zoneHoldRes = await checkZoneHold(hostname, c.env.CLOUDFLARE_API_TOKEN, c.env.CLOUDFLARE_ZONE_ID);

    // 5. Store in D1
    await c.env.hosts_db.prepare(`
            INSERT INTO hosts (hostname, authoritative_ns, is_proxied, dns_type, dns_result, ssl_google, ssl_ssl_com, ssl_lets_encrypt, zone_hold, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                authoritative_ns=excluded.authoritative_ns,
                is_proxied=excluded.is_proxied,
                dns_type=excluded.dns_type,
                dns_result=excluded.dns_result,
                ssl_google=excluded.ssl_google,
                ssl_ssl_com=excluded.ssl_ssl_com,
                ssl_lets_encrypt=excluded.ssl_lets_encrypt,
                zone_hold=excluded.zone_hold,
                updated_at=excluded.updated_at
        `).bind(
      hostname,
      authNs.join(', '),
      isProxied,
      dnsType,
      dnsResult,
      sslGoogle,
      sslSslCom,
      sslLetsEncrypt,
      zoneHoldRes.zone_hold,
      Date.now()
    ).run();

    return c.json({
      hostname,
      authoritative_ns: authNs,
      is_proxied: isProxied,
      dns_type: dnsType,
      dns_result: dnsResult,
      ssl_google: sslGoogle,
      ssl_ssl_com: sslSslCom,
      ssl_lets_encrypt: sslLetsEncrypt,
      zone_hold: zoneHoldRes.zone_hold,
      updated_at: Date.now()
    });

  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

app.get('/api/results', async (c) => {
  const results = await c.env.hosts_db.prepare('SELECT * FROM hosts ORDER BY updated_at DESC').all();
  return c.json(results.results);
});

export default app;
