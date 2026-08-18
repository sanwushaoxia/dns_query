from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass(frozen=True)
class LatencySample:
    ip: str
    latency_ms: float | None
    error: str | None = None


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


def pick_fastest_ipv4(ips: list[str], port: int = 443, timeout: float = 2.0) -> str | None:
    ipv4 = [ip for ip in ips if ":" not in ip]
    if not ipv4:
        return None
    for sample in measure_tcp_latency(ipv4, port=port, timeout=timeout):
        if sample.latency_ms is not None:
            return sample.ip
    return ipv4[0]
