export const CLOUDFLARE_IPV4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13", // 104.16.0.0 - 104.31.255.255
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
];

// Helper to check if IP is in CIDR
function ipInCidr(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);

    const ipParts = ip.split('.').map(Number);
    const rangeParts = range.split('.').map(Number);

    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const rangeNum = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];

    return (ipNum & mask) === (rangeNum & mask);
}

export function isCloudflareIp(ip: string): boolean {
    // Simple check for IPv4 only for now
    if (ip.includes(':')) return false; // TODO: IPv6 support
    return CLOUDFLARE_IPV4.some(cidr => ipInCidr(ip, cidr));
}

export interface ZoneHoldResult {
    zone_hold: 'yes' | 'no';
    details?: string;
}

export async function checkZoneHold(hostname: string, apiToken: string, zoneId: string): Promise<ZoneHoldResult> {
    if (!apiToken || !zoneId) {
        console.warn('Missing CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID');
        return { zone_hold: 'no', details: 'Missing credentials' };
    }

    const url = `https://api.cloudflare.com/client/v4/zones/${zoneId}/custom_hostnames`;
    const body = {
        hostname: hostname,
        ssl: { method: 'http', type: 'dv', settings: { http2: 'on' } }
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiToken}`
            },
            body: JSON.stringify(body)
        });

        const data: any = await response.json();

        if (response.ok && data.success) {
            // Created successfully, so NO hold. Delete it immediately.
            const id = data.result.id;
            await deleteCustomHostname(id, apiToken, zoneId);
            return { zone_hold: 'no' };
        } else {
            // Logic: If error code is 10000+ or specific "Hostname belongs to another account"
            // Usually error 1406: "Hostname ... is not a valid hostname"
            // Or something regarding ownership.

            // Common error for zone hold: "The hostname is being used by another account"
            const errors = data.errors || [];
            const isHeld = errors.some((e: any) =>
                e.message.toLowerCase().includes('another account') ||
                e.message.toLowerCase().includes('zone hold') ||
                e.code === 1010 // Error code might vary, reliance on message is safer but still brittle
            );

            if (isHeld) {
                return { zone_hold: 'yes', details: errors[0]?.message };
            }

            // Other errors (e.g. invalid hostname)
            return { zone_hold: 'no', details: errors[0]?.message || 'Unknown error' };
        }
    } catch (e) {
        console.error('Zone Hold Check Error:', e);
        return { zone_hold: 'no', details: 'API Error' };
    }
}

async function deleteCustomHostname(id: string, apiToken: string, zoneId: string) {
    await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/custom_hostnames/${id}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${apiToken}`
        }
    });
}
