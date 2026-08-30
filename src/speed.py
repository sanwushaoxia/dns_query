from __future__ import annotations

import socket
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass(frozen=True)
class LatencySample:
    ip: str
    latency_ms: float | None
    error: str | None = None


@dataclass(frozen=True)
class IpPick:
    ip: str
    latency_ms: float | None
    probes_ok: int
    probes_total: int


def _tcp_handshake(ip: str, port: int, timeout: float) -> float:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    start = socket.getaddrinfo(ip, port, family, socket.SOCK_STREAM)[0]
    sock = socket.socket(start[0], start[1])
    sock.settimeout(timeout)
    try:
        from time import perf_counter

        began = perf_counter()
        sock.connect(start[4])
        return (perf_counter() - began) * 1000
    finally:
        sock.close()


def _probe_ip(
    ip: str,
    port: int,
    timeout: float,
    probes: int,
) -> tuple[str, list[float]]:
    latencies: list[float] = []
    for _ in range(max(1, probes)):
        try:
            latencies.append(_tcp_handshake(ip, port, timeout))
        except OSError:
            continue
    return ip, latencies


def measure_tcp_latency(
    ips: list[str],
    port: int = 443,
    timeout: float = 2.0,
    workers: int = 16,
) -> list[LatencySample]:
    """Measure HTTPS-port TCP handshake time. ICMP ping is often blocked."""
    samples: list[LatencySample] = []

    def run(ip: str) -> LatencySample:
        try:
            return LatencySample(ip=ip, latency_ms=_tcp_handshake(ip, port, timeout))
        except OSError as exc:
            return LatencySample(ip=ip, latency_ms=None, error=exc.__class__.__name__)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run, ip): ip for ip in ips}
        for future in as_completed(futures):
            samples.append(future.result())

    samples.sort(key=lambda item: (item.latency_ms is None, item.latency_ms or 0.0))
    return samples


def pick_best_ipv4(
    ips: list[str],
    port: int = 443,
    timeout: float = 2.0,
    probes: int = 3,
    workers: int = 16,
) -> IpPick | None:
    """Pick an IPv4 with repeated :443 probes — favors reliability, then median latency."""
    ipv4 = [ip for ip in ips if ":" not in ip]
    if not ipv4:
        return None

    probe_count = max(1, probes)
    ranked: list[tuple[str, int, float]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_probe_ip, ip, port, timeout, probe_count) for ip in ipv4
        ]
        for future in as_completed(futures):
            ip, latencies = future.result()
            if latencies:
                ranked.append((ip, len(latencies), statistics.median(latencies)))

    if ranked:
        ranked.sort(key=lambda item: (-item[1], item[2]))
        ip, ok, median_ms = ranked[0]
        return IpPick(ip=ip, latency_ms=median_ms, probes_ok=ok, probes_total=probe_count)

    return IpPick(ip=ipv4[0], latency_ms=None, probes_ok=0, probes_total=probe_count)


def pick_fastest_ipv4(ips: list[str], port: int = 443, timeout: float = 2.0) -> str | None:
    pick = pick_best_ipv4(ips, port=port, timeout=timeout, probes=1)
    return pick.ip if pick else None
