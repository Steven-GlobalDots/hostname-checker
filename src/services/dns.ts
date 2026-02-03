export interface DnsAnswer {
    name: string;
    type: number;
    TTL: number;
    data: string;
}

export interface DnsResponse {
    Status: number;
    TC: boolean;
    RD: boolean;
    RA: boolean;
    AD: boolean;
    CD: boolean;
    Question: { name: string; type: number }[];
    Answer?: DnsAnswer[];
}

// DNS Record Types
export enum RecordType {
    A = 'A',
    AAAA = 'AAAA',
    CNAME = 'CNAME',
    NS = 'NS',
    CAA = 'CAA',
    TXT = 'TXT'
}

export async function dnsQuery(hostname: string, type: RecordType = RecordType.A): Promise<DnsResponse> {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${type}`;
    const response = await fetch(url, {
        headers: {
            'Accept': 'application/dns-json'
        },
        cf: {
            cacheTtl: 60,
            cacheEverything: true
        }
    });

    if (!response.ok) {
        throw new Error(`DNS query failed for ${hostname} (${type}): ${response.statusText}`);
    }

    return await response.json<DnsResponse>();
}

// Utility to extract authoritative NS
export function getAuthoritativeNS(response: DnsResponse): string[] {
    if (!response.Answer) return [];
    // Filter for NS records
    return response.Answer
        .filter(a => a.type === 2) // 2 is NS
        .map(a => a.data);
}

// Utility to Parse CAA records
// CAA format: "flag tag value" e.g., "0 issue \"letsencrypt.org\""
export interface ParsedCAA {
    critical: boolean;
    tag: string;
    value: string;
}

export function parseCAA(answer: DnsAnswer): ParsedCAA | null {
    if (answer.type !== 257) return null; // 257 is CAA

    // The data usually comes as a simpler string in DoH responses compared to binary, but let's handle the string format
    // Example DoH data: "\# 19 000569737375656C657473656E63727970742E6F7267" (RFC 3597 format) or "0 issue \"letsencrypt.org\""
    // Cloudflare DoH usually returns friendly format: "0 issue \"letsencrypt.org\""
    
    // Regex for: <flags> <tag> "<value>"
    const matcha = answer.data.match(/^(\d+)\s+(\w+)\s+(?:"(.*)"|(.*))$/);
    if (!matcha) return null;

    const flags = parseInt(matcha[1], 10);
    const tag = matcha[2];
    const value = matcha[3] || matcha[4]; 

    return {
        critical: !!(flags & 128),
        tag,
        value
    };
}
