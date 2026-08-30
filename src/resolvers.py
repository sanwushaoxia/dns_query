from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DnsResolver:
    """A classic UDP/TCP DNS server identified by IPv4."""

    name: str
    address: str


@dataclass(frozen=True)
class DohResolver:
    """A DNS-over-HTTPS JSON endpoint (RFC 8484 JSON / Google-style API)."""

    name: str
    url: str


# Public resolvers that are commonly reachable and useful for comparing answers.
DEFAULT_DNS_RESOLVERS: tuple[DnsResolver, ...] = (
    DnsResolver("Cloudflare", "1.1.1.1"),
    DnsResolver("Google", "8.8.8.8"),
    DnsResolver("Quad9", "9.9.9.9"),
    DnsResolver("AliDNS", "223.5.5.5"),
    DnsResolver("DNSPod", "119.29.29.29"),
    DnsResolver("OpenDNS", "208.67.222.222"),
)

FAST_DNS_RESOLVERS: tuple[DnsResolver, ...] = (
    DnsResolver("AliDNS", "223.5.5.5"),
    DnsResolver("Cloudflare", "1.1.1.1"),
)

DEFAULT_DOH_RESOLVERS: tuple[DohResolver, ...] = (
    DohResolver("Cloudflare DoH", "https://cloudflare-dns.com/dns-query"),
    DohResolver("Google DoH", "https://dns.google/resolve"),
    DohResolver("AliDNS DoH", "https://dns.alidns.com/resolve"),
)


def get_dns_resolvers(addresses: list[str] | None, *, fast: bool = False) -> list[DnsResolver]:
    if addresses:
        named = {item.address: item.name for item in DEFAULT_DNS_RESOLVERS}
        return [
            DnsResolver(name=named.get(address, address), address=address)
            for address in addresses
        ]
    if fast:
        return list(FAST_DNS_RESOLVERS)
    return list(DEFAULT_DNS_RESOLVERS)
