from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BEGIN_MARK = "# BEGIN dns-query managed"
END_MARK = "# END dns-query managed"
BACKUP_SUFFIX = ".dns-query.bak"
ORIG_SUFFIX = ".dns-query.orig"


def default_hosts_path() -> Path:
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(system_root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


DEFAULT_HOSTS = default_hosts_path()


def backup_store_dir(hosts_path: Path) -> Path:
    """Directory for hosts backups. On Windows, avoid writing beside hosts in System32."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        store = Path(base) / "dns-query" / "hosts-backups"
        store.mkdir(parents=True, exist_ok=True)
        return store
    return hosts_path.parent


def backup_path(hosts_path: Path) -> Path:
    return backup_store_dir(hosts_path) / (hosts_path.name + BACKUP_SUFFIX)


def orig_path(hosts_path: Path) -> Path:
    return backup_store_dir(hosts_path) / (hosts_path.name + ORIG_SUFFIX)


def _can_write(path: Path) -> bool:
    parent = path.parent if path.exists() else path.parent
    if path.exists():
        return os.access(path, os.W_OK)
    return os.access(parent, os.W_OK)


def _need_elevation_hint() -> str:
    if sys.platform == "win32":
        return "run as Administrator"
    return "need sudo"


def privileged_copy(src: Path, dst: Path) -> None:
    if _can_write(dst):
        shutil.copy2(src, dst)
        return
    if sys.platform == "win32":
        raise PermissionError(f"cannot copy {src} -> {dst} ({_need_elevation_hint()})")
    completed = subprocess.run(["sudo", "cp", "-a", str(src), str(dst)], check=False)
    if completed.returncode != 0:
        raise PermissionError(f"cannot copy {src} -> {dst} ({_need_elevation_hint()})")


def privileged_write(path: Path, content: str) -> None:
    if _can_write(path):
        path.write_text(content, encoding="utf-8", newline="\n")
        return
    if sys.platform == "win32" and _windows_write_hosts(path, content):
        return
    if sys.platform == "win32":
        raise PermissionError(
            f"cannot write {path} ({_need_elevation_hint()}). "
            "On Windows, open PowerShell or CMD as Administrator, not only Git Bash."
        )
    completed = subprocess.run(
        ["sudo", "tee", str(path)],
        input=content.encode("utf-8"),
        stdout=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise PermissionError(f"cannot write {path} ({_need_elevation_hint()})")


def _windows_write_hosts(path: Path, content: str) -> bool:
    """Write hosts via PowerShell when the current process lacks direct access."""
    tmp = Path(tempfile.gettempdir()) / f"dns-query-hosts-{os.getpid()}.tmp"
    try:
        tmp.write_text(content, encoding="utf-8", newline="\n")
        ps = (
            f"$src = '{tmp}'; $dst = '{path}'; "
            f"Copy-Item -LiteralPath $src -Destination $dst -Force"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            check=False,
            capture_output=True,
            text=True,
        )
        return completed.returncode == 0
    finally:
        tmp.unlink(missing_ok=True)


def privileged_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except PermissionError:
        if sys.platform == "win32":
            raise PermissionError(f"cannot read {path} ({_need_elevation_hint()})") from None
        completed = subprocess.run(
            ["sudo", "cat", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise PermissionError(f"cannot read {path}") from None
        return completed.stdout


def strip_managed_block(text: str) -> str:
    lines = text.splitlines()
    kept: list[str] = []
    skipping = False
    for line in lines:
        stripped = line.strip()
        if stripped == BEGIN_MARK:
            skipping = True
            continue
        if stripped == END_MARK:
            skipping = False
            continue
        if not skipping:
            kept.append(line)
    return "\n".join(kept).rstrip() + "\n"


def _hostnames(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []
    parts = stripped.split()
    if len(parts) < 2:
        return []
    return [name.lower().rstrip(".") for name in parts[1:]]


def strip_domain_lines(text: str, domains: set[str]) -> tuple[str, list[str]]:
    """Drop hosts lines that mention any managed domain. Keep the rest intact."""
    removed: list[str] = []
    kept: list[str] = []
    for line in text.splitlines():
        names = _hostnames(line)
        if names and any(name in domains for name in names):
            removed.append(line)
            continue
        kept.append(line)
    return "\n".join(kept).rstrip() + "\n", removed


def extract_managed_block(text: str) -> str | None:
    lines = text.splitlines()
    inside: list[str] = []
    capturing = False
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped == BEGIN_MARK:
            capturing = True
            found = True
            continue
        if stripped == END_MARK:
            capturing = False
            continue
        if capturing:
            inside.append(line)
    if not found:
        return None
    return "\n".join(inside).rstrip() + "\n"


def render_managed_block(entries: list[tuple[str, str]], stamp: str | None = None) -> str:
    when = stamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        BEGIN_MARK,
        f"# Generated by dns-query at {when}",
        "# CDN IPs change; re-run src/apply-hosts.sh to refresh.",
    ]
    for ip, domain in entries:
        lines.append(f"{ip:<20} {domain}")
    lines.append(END_MARK)
    return "\n".join(lines) + "\n"


def merge_hosts(original: str, entries: list[tuple[str, str]]) -> tuple[str, list[str]]:
    domains = {domain for _, domain in entries}
    without_block = strip_managed_block(original)
    cleaned, removed = strip_domain_lines(without_block, domains)
    merged = cleaned.rstrip() + "\n\n" + render_managed_block(entries)
    return merged, removed


def backup_hosts(hosts_path: Path) -> tuple[Path, Path | None]:
    bak = backup_path(hosts_path)
    privileged_copy(hosts_path, bak)
    original = orig_path(hosts_path)
    created_orig = None
    if not original.exists():
        privileged_copy(hosts_path, original)
        created_orig = original
    return bak, created_orig


def apply_entries(hosts_path: Path, entries: list[tuple[str, str]]) -> tuple[str, list[str], Path]:
    current = privileged_read(hosts_path)
    merged, removed = merge_hosts(current, entries)
    bak, _ = backup_hosts(hosts_path)
    privileged_write(hosts_path, merged)
    return merged, removed, bak


def remove_managed(hosts_path: Path) -> bool:
    current = privileged_read(hosts_path)
    if extract_managed_block(current) is None:
        return False
    bak, _ = backup_hosts(hosts_path)
    privileged_write(hosts_path, strip_managed_block(current))
    return True


def restore_hosts(hosts_path: Path) -> Path:
    original = orig_path(hosts_path)
    bak = backup_path(hosts_path)
    source = original if original.exists() else bak
    if not source.exists():
        raise FileNotFoundError(f"no backup found at {original} or {bak}")
    privileged_copy(source, hosts_path)
    return source


def flush_dns_cache() -> str | None:
    if sys.platform == "win32":
        try:
            completed = subprocess.run(
                ["ipconfig", "/flushdns"],
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return None
        if completed.returncode == 0:
            return "ipconfig /flushdns"
        return None

    candidates = (
        ["resolvectl", "flush-caches"],
        ["systemd-resolve", "--flush-caches"],
    )
    for command in candidates:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if completed.returncode == 0:
            return " ".join(command)
        completed = subprocess.run(["sudo", *command], check=False, capture_output=True, text=True)
        if completed.returncode == 0:
            return "sudo " + " ".join(command)
    return None
