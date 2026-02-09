import { WorkflowEntrypoint, WorkflowStep, WorkflowEvent } from 'cloudflare:workers';
import { Bindings, RecordType } from './types';
import { dnsQuery } from './services/dns';
import { isCloudflareIp, checkZoneHold, isCloudflareManaged } from './services/cloudflare';

type WorkflowParams = {
    hostname: string;
    jobId: string;
};

export class HostCheckWorkflow extends WorkflowEntrypoint<Bindings, WorkflowParams> {
    async run(event: WorkflowEvent<WorkflowParams>, step: WorkflowStep) {
        const { hostname, jobId } = event.payload;

        try {
            // 1. Update Job Status to Running
            await step.do('update-job-running', async () => {
                await this.env.hosts_db.prepare(
                    `UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ?`
                ).bind(Date.now(), jobId).run();
            });

            // 2. DNS Lookup (A Record)
            const aRecord = await step.do('dns-lookup', async () => {
                return await dnsQuery(hostname, RecordType.A);
            });

            const dnsType = 'A';
            let dnsResult = '';
            let isProxied = 'no';

            if (aRecord.Answer && aRecord.Answer.length > 0) {
                const ips = aRecord.Answer.filter(a => a.type === 1).map(a => a.data);
                dnsResult = ips.join(', ');
                const cfCheck = await step.do('check-cf-ip', async () => {
                    // isCloudflareIp is synchronous/local but we wrap it for consistency or if we want to memoize, 
                    // though for purely CPU tasks specific to the data it's not strictly necessary. 
                    // But logic often changes. 
                    // Actually isCloudflareIp is just a helper. We can run it here.
                    return ips.some(ip => isCloudflareIp(ip));
                });
                if (cfCheck) {
                    isProxied = 'yes';
                }
            }

            // 3. Authoritative NS
            const authNs: string[] = await step.do('get-auth-ns', async () => {
                // Re-implementing getAuthoritativeNameservers logic here or importing it?
                // Importing is better but it was in handler. Let's inline or move it.
                // For now, I'll inline the logic using the service
                let nsRecord = await dnsQuery(hostname, RecordType.NS);
                let ans = nsRecord.Answer?.filter(a => a.type === 2).map(a => a.data) || [];

                if (ans.length === 0) {
                    const parent = hostname.split('.').slice(1).join('.');
                    if (parent) {
                        nsRecord = await dnsQuery(parent, RecordType.NS);
                        ans = nsRecord.Answer?.filter(a => a.type === 2).map(a => a.data) || [];
                    }
                }
                return ans;
            });

            // 4. CAA Check
            const caaCheckResult = await step.do('caa-check', async () => {
                let caaRes = await dnsQuery(hostname, RecordType.CAA);
                let caaAnswers = caaRes.Answer || [];
                if (caaAnswers.length === 0) {
                    const parent = hostname.split('.').slice(1).join('.');
                    if (parent) {
                        caaRes = await dnsQuery(parent, RecordType.CAA);
                        caaAnswers = caaRes.Answer || [];
                    }
                }
                // We return the raw answers to parse outside, or parse inside.
                // Parse inside to return simple boolean/string data is safer for serialization.
                // But we need the helper function 'parseCAA'.
                // I'll return the raw answers and process them in the workflow main scope? 
                // No, step.do output must be JSON serializable.
                return caaAnswers;
            });

            // Logic to process CAA (moved from handler)
            // Need to import parseCAA from handlers or duplicate. 
            // It was in handler, but dns service has `parseCAA`. Let's use the one in `services/dns.ts`
            // Wait, `services/dns.ts` has `parseCAA`.
            const { parseCAA: parseCAAHelper } = await import('./services/dns');

            const parsedCaas = caaCheckResult.map(a => parseCAAHelper(a)).filter(x => x !== null);

            const checkCaa = (domain: string) => {
                if (!parsedCaas || parsedCaas.length === 0) return 'allowed';
                const allowed = parsedCaas.some(r => {
                    if (r.tag !== 'issue' && r.tag !== 'issuewild') return false;
                    return r.value.includes(domain);
                });
                return allowed ? 'allowed' : 'not_allowed';
            };

            const sslGoogle = checkCaa('pki.goog');
            const sslSslCom = checkCaa('ssl.com');
            const sslLetsEncrypt = checkCaa('letsencrypt.org');


            // 5. Zone Hold
            const zoneHoldRes = await step.do('zone-hold-check', async () => {
                const isCfManaged = isCloudflareManaged(authNs);

                if (isCfManaged) {
                    const apiCheck = await checkZoneHold(hostname, this.env.CLOUDFLARE_API_TOKEN, this.env.CLOUDFLARE_ZONE_ID);
                    if (apiCheck.zone_hold === 'yes') {
                        return { ...apiCheck, verification_method: 'api' };
                    } else {
                        return {
                            zone_hold: 'likely',
                            details: 'Domain uses Cloudflare nameservers - likely managed by another CF account',
                            verification_method: 'nameserver_inference'
                        };
                    }
                } else {
                    const res = await checkZoneHold(hostname, this.env.CLOUDFLARE_API_TOKEN, this.env.CLOUDFLARE_ZONE_ID);
                    if (!res.verification_method) res.verification_method = 'api';
                    return res;
                }
            });

            // 6. Save Result
            const finResult = {
                hostname,
                authoritative_ns: authNs,
                is_proxied: isProxied,
                dns_type: dnsType,
                dns_result: dnsResult,
                ssl_google: sslGoogle,
                ssl_ssl_com: sslSslCom,
                ssl_lets_encrypt: sslLetsEncrypt,
                updated_at: Date.now(),
                zone_hold: zoneHoldRes.zone_hold // Add this to result
            };

            await step.do('save-to-db', async () => {
                // Save to 'hosts' table
                await this.env.hosts_db.prepare(`
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

                // Update 'jobs' table
                await this.env.hosts_db.prepare(
                    `UPDATE jobs SET status = 'completed', result = ?, updated_at = ? WHERE id = ?`
                ).bind(JSON.stringify(finResult), Date.now(), jobId).run();
            });

        } catch (e: any) {
            await step.do('handle-failure', async () => {
                await this.env.hosts_db.prepare(
                    `UPDATE jobs SET status = 'failed', result = ?, updated_at = ? WHERE id = ?`
                ).bind(JSON.stringify({ error: e.message }), Date.now(), jobId).run();
            });
        }
    }
}
