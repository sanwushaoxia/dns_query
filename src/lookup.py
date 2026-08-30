from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable, Literal

import dns.exception
import dns.resolver

from .resolvers import DEFAULT_DOH_RESOLVERS, DnsResolver, DohResolver, get_dns_resolvers

RECORD_TYPES = ("A", "AAAA")
FALLBACK_TIMEOUT = 2.0
EARLY_EXIT_MIN_RESPONSES = 3

JobKind = Literal["classic", "doh", "system", "os"]

_classic_resolvers: dict[str, dns.resolver.Resolver] = {}


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


def _classic_resolver(address: str, timeout: float) -> dns.resolver.Resolver:
    cached = _classic_resolvers.get(address)
    if cached is not None:
        cached.lifetime = timeout
        cached.timeout = timeout
        return cached

    stub = dns.resolver.Resolver(configure=False)
    stub.nameservers = [address]
    stub.lifetime = timeout
    stub.timeout = timeout
    _classic_resolvers[address] = stub
    return stub


def _query_classic(
    domain: str,
    resolver: DnsResolver,
    record_type: str,
    timeout: float,
) -> list[AddressHit]:
    stub = _classic_resolver(resolver.address, timeout)
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


def _query_system(
    domain: str,
    record_type: str,
    timeout: float,
) -> list[AddressHit]:
    stub = dns.resolver.Resolver(configure=True)
    stub.lifetime = timeout
    stub.timeout = timeout
    answers = stub.resolve(domain, record_type)
    return [
        AddressHit(ip=rdata.address, record_type=record_type, source="system DNS")
        for rdata in answers
    ]


def _query_os_resolver(domain: str, record_type: str) -> list[AddressHit]:
    """Use the OS native resolver (reliable on Windows when UDP DNS to public servers is blocked)."""
    if record_type == "A":
        family = socket.AF_INET
    elif record_type == "AAAA":
        family = socket.AF_INET6
    else:
        return []

    infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
    ips = unique_ips(info[4][0] for info in infos)
    return [AddressHit(ip=ip, record_type=record_type, source="OS resolver") for ip in ips]


def _run_job(
    kind: JobKind,
    domain: str,
    record_type: str,
    timeout: float,
    resolver: DnsResolver | DohResolver | None,
) -> tuple[list[AddressHit], str | None]:
    label = resolver.name if resolver is not None else kind
    try:
        if kind == "classic" and isinstance(resolver, DnsResolver):
            return _query_classic(domain, resolver, record_type, timeout), None
        if kind == "doh" and isinstance(resolver, DohResolver):
            return _query_doh(domain, resolver, record_type, timeout), None
        if kind == "system":
            return _query_system(domain, record_type, timeout), None
        if kind == "os":
            return _query_os_resolver(domain, record_type), None
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
        return [], f"{label} {record_type}: {exc.__class__.__name__}"
    except Exception as exc:  # noqa: BLE001 - keep the CLI running
        return [], f"{label} {record_type}: {exc}"
    return [], f"{label} {record_type}: unknown job"


def _has_record_hit(result: LookupResult, record_types: tuple[str, ...]) -> bool:
    return any(hit.record_type in record_types for hit in result.hits)


def _should_stop(
    result: LookupResult,
    completed: int,
    *,
    fast: bool,
    record_types: tuple[str, ...],
) -> bool:
    if not _has_record_hit(result, record_types):
        return False
    if fast:
        return True
    return completed >= EARLY_EXIT_MIN_RESPONSES


def _cancel_pending(futures: dict[Future, object]) -> None:
    for future in futures:
        future.cancel()


def query_domain(
    domain: str,
    dns_servers: list[str] | None = None,
    use_doh: bool = True,
    record_types: Iterable[str] = RECORD_TYPES,
    timeout: float = 3.0,
    workers: int = 12,
    *,
    fast: bool = False,
    fallback_timeout: float = FALLBACK_TIMEOUT,
) -> LookupResult:
    """Resolve a domain via public DNS, DoH, and parallel system/OS fallbacks."""
    result = LookupResult(domain=domain)
    types = tuple(record_types)
    effective_doh = use_doh and not fast

    jobs: list[tuple[JobKind, DnsResolver | DohResolver | None, str, float]] = []
    for resolver in get_dns_resolvers(dns_servers, fast=fast):
        for record_type in types:
            jobs.append(("classic", resolver, record_type, timeout))

    if effective_doh:
        for resolver in DEFAULT_DOH_RESOLVERS:
            for record_type in types:
                jobs.append(("doh", resolver, record_type, timeout))

    for record_type in types:
        jobs.append(("system", None, record_type, fallback_timeout))
        jobs.append(("os", None, record_type, fallback_timeout))

    pending: dict[Future, tuple[JobKind, str]] = {}
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        for kind, resolver, record_type, job_timeout in jobs:
            future = pool.submit(_run_job, kind, domain, record_type, job_timeout, resolver)
            pending[future] = (kind, record_type)

        completed = 0
        for future in as_completed(pending):
            _kind, record_type = pending[future]
            hits, error = future.result()
            if hits:
                result.hits.extend(hits)
            elif error:
                result.errors.append(error)
            completed += 1
            if _should_stop(result, completed, fast=fast, record_types=types):
                _cancel_pending(pending)
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return result


def query_domains(
    domains: Iterable[str],
    *,
    domain_workers: int = 8,
    **kwargs,
) -> list[LookupResult]:
    """Resolve many domains in parallel, preserving input order."""
    ordered = list(domains)
    if not ordered:
        return []
    if len(ordered) == 1:
        return [query_domain(ordered[0], **kwargs)]

    by_domain: dict[str, LookupResult] = {}
    pool = ThreadPoolExecutor(max_workers=domain_workers)
    try:
        futures = {pool.submit(query_domain, domain, **kwargs): domain for domain in ordered}
        for future in as_completed(futures):
            domain = futures[future]
            by_domain[domain] = future.result()
    finally:
        pool.shutdown(wait=True)

    return [by_domain[domain] for domain in ordered]
