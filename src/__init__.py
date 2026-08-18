"""Domain-to-IP lookup using public DNS / DoH resolvers."""

from .lookup import LookupResult, query_domain, query_domains
from .speed import measure_tcp_latency

__all__ = [
    "LookupResult",
    "measure_tcp_latency",
    "query_domain",
    "query_domains",
]
__version__ = "0.1.0"
