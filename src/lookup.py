from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable

import dns.exception
import dns.resolver

from .resolvers import DEFAULT_DOH_RESOLVERS, DnsResolver, DohResolver, get_dns_resolvers

RECORD_TYPES = ("A", "AAAA")


@dataclass
class AddressHit:
    ip: str
    record_type: str
    source: str


@dataclass
class LookupResult:
    domain: str
    hits: list[AddressHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ipv4(self) -> list[str]:
        return unique_ips(hit.ip for hit in self.hits if hit.record_type == "A")

    @property
    def ipv6(self) -> list[str]:
        return unique_ips(hit.ip for hit in self.hits if hit.record_type == "AAAA")

    @property
    def ips(self) -> list[str]:
        return unique_ips(hit.ip for hit in self.hits)


def unique_ips(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _query_classic(
    domain: str,
    resolver: DnsResolver,
    record_type: str,
    timeout: float,
) -> list[AddressHit]:
    stub = dns.resolver.Resolver(configure=False)
    stub.nameservers = [resolver.address]
    stub.lifetime = timeout
    stub.timeout = timeout
    answers = stub.resolve(domain, record_type)
    return [
        AddressHit(ip=rdata.address, record_type=record_type, source=resolver.name)
        for rdata in answers
    ]


def _query_doh(
    domain: str,
    resolver: DohResolver,
    record_type: str,
    timeout: float,
) -> list[AddressHit]:
    separator = "&" if "?" in resolver.url else "?"
    url = f"{resolver.url}{separator}name={domain}&type={record_type}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/dns-json",
            "User-Agent": "dns-query/0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    hits: list[AddressHit] = []
    for answer in payload.get("Answer") or []:
        if answer.get("type") in (1, 28) and answer.get("data"):
            record = "A" if answer["type"] == 1 else "AAAA"
            if record == record_type:
                hits.append(
                    AddressHit(ip=answer["data"], record_type=record, source=resolver.name)
                )
    return hits


def query_domain(
    domain: str,
    dns_servers: list[str] | None = None,
    use_doh: bool = True,
    record_types: Iterable[str] = RECORD_TYPES,
    timeout: float = 3.0,
    workers: int = 12,
) -> LookupResult:
    """Resolve a domain via multiple public DNS servers and optional DoH endpoints."""
    result = LookupResult(domain=domain)
    jobs: list[tuple[str, object, str]] = []

    for resolver in get_dns_resolvers(dns_servers):
        for record_type in record_types:
            jobs.append(("classic", resolver, record_type))

    if use_doh:
        for resolver in DEFAULT_DOH_RESOLVERS:
            for record_type in record_types:
                jobs.append(("doh", resolver, record_type))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for kind, resolver, record_type in jobs:
            if kind == "classic":
                future = pool.submit(_query_classic, domain, resolver, record_type, timeout)
            else:
                future = pool.submit(_query_doh, domain, resolver, record_type, timeout)
            futures[future] = (kind, resolver, record_type)

        for future in as_completed(futures):
            kind, resolver, record_type = futures[future]
            source = resolver.name
            try:
                result.hits.extend(future.result())
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                urllib.error.URLError,
                TimeoutError,
                json.JSONDecodeError,
                OSError,
            ) as exc:
                result.errors.append(f"{source} {record_type}: {exc.__class__.__name__}")
            except Exception as exc:  # noqa: BLE001 - keep the CLI running
                result.errors.append(f"{source} {record_type}: {exc}")

    return result


def query_domains(
    domains: Iterable[str],
    **kwargs,
) -> list[LookupResult]:
    return [query_domain(domain, **kwargs) for domain in domains]
