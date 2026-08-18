from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cli import choose_ip, collect_domains
from .hostsfile import (
    DEFAULT_HOSTS,
    apply_entries,
    extract_managed_block,
    flush_dns_cache,
    merge_hosts,
    privileged_read,
    remove_managed,
    render_managed_block,
    restore_hosts,
)
from .lookup import query_domain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apply-hosts",
        description="Query fastest IPs and update a marked block in /etc/hosts.",
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=("apply", "preview", "remove", "restore", "status"),
        default="preview",
        help="preview (default), apply, remove managed block, restore backup, or show status",
    )
    parser.add_argument("domains", nargs="*", help="Extra domains, e.g. github.com")
    parser.add_argument("--preset", default=None, help="Domain preset (default: github when none given)")
    parser.add_argument("--from-file", type=Path, help="Read domains from a file")
    parser.add_argument("--dns", action="append", dest="dns_servers", metavar="IP")
    parser.add_argument("--no-doh", action="store_true")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--hosts-file", type=Path, default=DEFAULT_HOSTS)
    parser.add_argument("-y", "--yes", action="store_true", help="Do not prompt before writing")
    return parser


def resolve_entries(args: argparse.Namespace) -> list[tuple[str, str]]:
    if args.preset is None and not args.domains and not args.from_file:
        args.preset = "github"
    domains = collect_domains(args)
    if not domains:
        raise SystemExit("no domains to resolve")

    entries: list[tuple[str, str]] = []
    print(f"querying {len(domains)} domain(s)...", file=sys.stderr)
    for domain in domains:
        result = query_domain(
            domain,
            dns_servers=args.dns_servers,
            use_doh=not args.no_doh,
            record_types=("A",),
            timeout=args.timeout,
        )
        ip = choose_ip(result, fastest=True)
        if ip:
            print(f"  {domain} -> {ip}", file=sys.stderr)
            entries.append((ip, domain))
        else:
            print(f"  {domain} -> unresolved (skipped)", file=sys.stderr)
    return entries


def confirm(prompt: str) -> bool:
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def cmd_preview(args: argparse.Namespace) -> int:
    entries = resolve_entries(args)
    if not entries:
        print("no resolvable domains", file=sys.stderr)
        return 1
    current = privileged_read(args.hosts_file)
    merged, removed = merge_hosts(current, entries)
    print(render_managed_block(entries), end="")
    if removed:
        print(f"# would replace {len(removed)} existing hosts line(s)", file=sys.stderr)
    print(
        f"# dry-run only; run: ./src/apply-hosts.sh apply   to write {args.hosts_file}",
        file=sys.stderr,
    )
    _ = merged
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    entries = resolve_entries(args)
    if not entries:
        print("no resolvable domains", file=sys.stderr)
        return 1
    print(render_managed_block(entries), end="")
    if not args.yes and not confirm(f"write {len(entries)} entries to {args.hosts_file}? [y/N] "):
        print("aborted", file=sys.stderr)
        return 130
    _, removed, bak = apply_entries(args.hosts_file, entries)
    print(f"updated {args.hosts_file} ({len(entries)} entries)", file=sys.stderr)
    print(f"backup: {bak}", file=sys.stderr)
    if removed:
        print(f"replaced {len(removed)} previous hosts line(s)", file=sys.stderr)
    flushed = flush_dns_cache()
    if flushed:
        print(f"flushed DNS cache via {flushed}", file=sys.stderr)
    else:
        print("hosts updated; flush local DNS cache if the old IP is still used", file=sys.stderr)
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    if not args.yes and not confirm(f"remove dns-query block from {args.hosts_file}? [y/N] "):
        print("aborted", file=sys.stderr)
        return 130
    if remove_managed(args.hosts_file):
        print(f"removed managed block from {args.hosts_file}", file=sys.stderr)
        flush_dns_cache()
        return 0
    print("no managed block found", file=sys.stderr)
    return 1


def cmd_restore(args: argparse.Namespace) -> int:
    if not args.yes and not confirm(f"restore {args.hosts_file} from backup? [y/N] "):
        print("aborted", file=sys.stderr)
        return 130
    source = restore_hosts(args.hosts_file)
    print(f"restored {args.hosts_file} from {source}", file=sys.stderr)
    flush_dns_cache()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    current = privileged_read(args.hosts_file)
    block = extract_managed_block(current)
    if block is None:
        print(f"no dns-query managed block in {args.hosts_file}")
        return 1
    print(block, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    actions = {
        "preview": cmd_preview,
        "apply": cmd_apply,
        "remove": cmd_remove,
        "restore": cmd_restore,
        "status": cmd_status,
    }
    try:
        return actions[args.action](args)
    except (PermissionError, FileNotFoundError) as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
