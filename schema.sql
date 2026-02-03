CREATE TABLE hosts (
    hostname TEXT PRIMARY KEY,
    authoritative_ns TEXT,
    is_proxied TEXT CHECK(is_proxied IN ('yes', 'no')),
    dns_type TEXT,
    dns_result TEXT,
    ssl_google TEXT CHECK(ssl_google IN ('allowed', 'not_allowed')),
    ssl_ssl_com TEXT CHECK(ssl_ssl_com IN ('allowed', 'not_allowed')),
    ssl_lets_encrypt TEXT CHECK(ssl_lets_encrypt IN ('allowed', 'not_allowed')),
    zone_hold TEXT CHECK(zone_hold IN ('yes', 'no')),
    updated_at INTEGER
);
