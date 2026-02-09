// import { Workflow } from '@cloudflare/workers-types'; // Removed as we use generated types

export interface Bindings {
    hosts_db: D1Database;
    CLOUDFLARE_API_TOKEN: string;
    CLOUDFLARE_ZONE_ID: string;
    HOST_CHECK_WORKFLOW: Workflow;
}

export interface Job {
    id: string;
    hostname: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    result?: string; // JSON string
    created_at: number;
    updated_at: number;
}

export interface ErrorResponse {
    success: false;
    error: string;
    code: string;
    details?: unknown;
}

export interface SuccessResponse<T> {
    success: true;
    data: T;
}

// DNS Types
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

export enum RecordType {
    A = 'A',
    AAAA = 'AAAA',
    CNAME = 'CNAME',
    NS = 'NS',
    CAA = 'CAA',
    TXT = 'TXT'
}

export interface ZoneHoldResult {
    zone_hold: 'yes' | 'no';
    details?: string;
}
