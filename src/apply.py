from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .cli import collect_domains
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
from .lookup import query_domains
from .speed import pick_best_ipv4

GITHUB_SHORTCUTS = frozenset({"github.com", "www.github.com"})


def maybe_expand_github_preset(args: argparse.Namespace) -> None:
    if args.preset or args.from_file:
        return
    shortcuts = {domain.lower().rstrip(".") for domain in args.domains}
    if shortcuts and shortcuts.issubset(GITHUB_SHORTCUTS):
        print(
            "note: expanding to --preset github (git, API, assets, raw, avatars, ...)",
            file=sys.stderr,
        )
        args.preset = "github"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apply-hosts",
        description="Query fastest IPs and update a marked block in the system hosts file.",
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
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Parallel domain queries (default: 8)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Fast mode: fewer resolvers, skip DoH, stop after first useful answer, 1 TCP probe",
    )
    parser.add_argument(
        "--probes",
        type=int,
        default=3,
        metavar="N",
        help="TCP :443 probes per IP when picking the fastest address (default: 3)",
    )
    parser.add_argument("--hosts-file", type=Path, default=DEFAULT_HOSTS)
    parser.add_argument("-y", "--yes", action="store_true", help="Do not prompt before writing")
    return parser


def resolve_entries(args: argparse.Namespace) -> list[tuple[str, str]]:
    if args.preset is None and not args.domains and not args.from_file:
        args.preset = "github"
    maybe_expand_github_preset(args)
    domains = collect_domains(args)
    if not domains:
        raise SystemExit("no domains to resolve")

    entries: list[tuple[str, str]] = []
    probes = 1 if args.fast else max(1, args.probes)
    print(f"querying {len(domains)} domain(s)...", file=sys.stderr)
    results = query_domains(
        domains,
        dns_servers=args.dns_servers,
        use_doh=not args.no_doh,
        record_types=("A",),
        timeout=args.timeout,
        domain_workers=max(1, args.workers),
        fast=args.fast,
    )
    for result in results:
        domain = result.domain
        pick = pick_best_ipv4(result.ipv4, probes=probes)
        if pick:
            detail = f"{pick.probes_ok}/{pick.probes_total} probes"
            if pick.latency_ms is not None:
                detail = f"{pick.latency_ms:.0f} ms, {detail}"
            sources = len({hit.source for hit in result.hits if hit.ip == pick.ip})
            if sources > 1:
                detail += f", {sources} DNS sources"
            if pick.probes_ok == 0:
                detail += ", probe failed"
            print(f"  {domain} -> {pick.ip} ({detail})", file=sys.stderr)
            if pick.probes_ok == 0:
                print(f"    :443 probe failed for {domain}; using DNS answer", file=sys.stderr)
            elif len(result.ipv4) == 1 and any(
                hit.source in {"OS resolver", "system DNS"} for hit in result.hits
            ):
                print(
                    f"    only one IP candidate for {domain}; public DNS may be blocked",
                    file=sys.stderr,
                )
            entries.append((pick.ip, domain))
        else:
            print(f"  {domain} -> unresolved (skipped)", file=sys.stderr)
            if result.errors:
                print("    DNS errors:", file=sys.stderr)
                for err in result.errors[:6]:
                    print(f"      {err}", file=sys.stderr)
                if len(result.errors) > 6:
                    print(f"      ... and {len(result.errors) - 6} more", file=sys.stderr)
                print(
                    "    tip: try --dns <your-router-dns> or --timeout 10 if public DNS is blocked",
                    file=sys.stderr,
                )
    return entries


def _read_confirm_line() -> str:
    """Read a line for y/N prompts; works in Linux terminals and Git Bash on Windows."""
    if sys.stdin.isatty():
        try:
            return input().strip().lower()
        except EOFError:
            return ""

    try:
        line = sys.stdin.readline()
        if line:
            return line.strip().lower()
    except EOFError:
        pass

    if sys.platform == "win32":
        try:
            with open("CONIN$", "r", encoding="utf-8", errors="replace") as console:
                return console.readline().strip().lower()
        except OSError:
            pass

    return ""


def confirm(prompt: str) -> bool:
    sys.stderr.write(prompt)
    sys.stderr.flush()
    return _read_confirm_line() in {"y", "yes"}


def write_entries(args: argparse.Namespace, entries: list[tuple[str, str]]) -> int:
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


def cmd_preview(args: argparse.Namespace) -> int:
    entries = resolve_entries(args)
    if not entries:
        print("no resolvable domains", file=sys.stderr)
        return 1
    current = privileged_read(args.hosts_file)
    _, removed = merge_hosts(current, entries)
    print(render_managed_block(entries), end="")
    sys.stdout.flush()
    if removed:
        print(f"# would replace {len(removed)} existing hosts line(s)", file=sys.stderr)

    if args.yes or confirm(f"write {len(entries)} entries to {args.hosts_file}? [y/N] "):
        return write_entries(args, entries)

    print("aborted", file=sys.stderr)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    entries = resolve_entries(args)
    if not entries:
        print("no resolvable domains", file=sys.stderr)
        return 1
    print(render_managed_block(entries), end="")
    sys.stdout.flush()
    if not args.yes and not confirm(f"write {len(entries)} entries to {args.hosts_file}? [y/N] "):
        print("aborted", file=sys.stderr)
        return 130
    return write_entries(args, entries)


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
