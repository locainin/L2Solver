#!/usr/bin/python3 -I
"""Publish a reviewed, prebuilt Linux payload; also serve as the installed uninstaller."""
import argparse
import fcntl
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

BINARIES = ("l2solver", "l2solver-active", "l2solver-active-helper")
FILES = (*BINARIES, "l2solver-uninstall", "bash", "zsh", "fish", "README.md", "install.md", "NOTICE-JEMALLOC.txt", "receipt.json")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_parents(path):
    # Never follow an administrator's destination through an untrusted directory
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise ValueError(f"symlink directory refused: {parent}")
        if parent.exists():
            info = parent.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                # Sticky temporary roots protect existing directories owned by another account
                if parent == Path(tempfile.gettempdir()) and info.st_mode & stat.S_ISVTX:
                    continue
                raise ValueError(f"untrusted directory: {parent}")


def links(prefix):
    result = {f"bin/{name}": f"../share/l2solver/current/{name}" for name in (*BINARIES, "l2solver-uninstall")}
    # Probe existing prefix directories rather than writing into distribution paths
    candidates = {
        "bash": ("share/bash-completion/completions", "etc/bash_completion.d"),
        "zsh": ("share/zsh/site-functions", "share/zsh/functions/Completion"),
        "fish": ("share/fish/vendor_completions.d", "share/fish/completions"),
    }
    for shell, choices in candidates.items():
        directory = next((item for item in choices if (prefix / item).is_dir()), choices[0])
        name = {"bash": "l2solver", "zsh": "_l2solver", "fish": "l2solver.fish"}[shell]
        destination = f"{directory}/{name}"
        result[destination] = os.path.relpath(prefix / "share/l2solver/current" / shell, (prefix / destination).parent)
    return result


def read_manifest(prefix):
    base = prefix / "share/l2solver"
    path = base / "manifest.json"
    if not path.exists():
        if base.exists():
            raise ValueError(f"unrecognized installation tree: {base}")
        return None
    safe_parents(base)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("unsafe installation manifest")
    data = json.loads(path.read_text())
    if set(data) != {"schema", "links", "generations"} or data["schema"] != 1 or not data["generations"]:
        raise ValueError("unrecognized installation manifest")
    # Stored paths must match one of the finite supported completion layouts
    permitted = links(prefix)
    for relative, target in data["links"].items():
        if permitted.get(relative) != target:
            raise ValueError(f"unsafe manifest link: {relative}")
    if set(data["links"]) != set(permitted):
        raise ValueError("incompatible completion layout; restore previous directories")
    for generation, hashes in data["generations"].items():
        if not re.fullmatch(r"[0-9a-f]{64}", generation) or set(hashes) != set(FILES):
            raise ValueError("unsafe manifest generation")
        directory = base / generation
        safe_parents(directory)
        if set(item.name for item in directory.iterdir()) != set(FILES):
            raise ValueError(f"modified installation directory: {directory}")
        for name, expected in hashes.items():
            entry = directory / name
            info = entry.lstat()
            mode = 0o755 if name in (*BINARIES, "l2solver-uninstall") else 0o644
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode or digest(entry) != expected:
                raise ValueError(f"modified installed file: {entry}")
    for relative, target in data["links"].items():
        entry = prefix / relative
        safe_parents(entry.parent)
        if not entry.is_symlink() or os.readlink(entry) != target:
            raise ValueError(f"modified installation link: {entry}")
    current = base / "current"
    if not current.is_symlink() or os.readlink(current) not in data["generations"]:
        raise ValueError("unsafe current generation")
    if set(item.name for item in base.iterdir()) != {*data["generations"], "current", "manifest.json"}:
        raise ValueError("unrecognized files in installation tree")
    return data


def write_manifest(base, data):
    path = base / ".manifest-new"
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(path, base / "manifest.json")
    directory_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def enable_capability(helper):
    subprocess.run(["/usr/sbin/setcap" if Path("/usr/sbin/setcap").exists() else "/usr/bin/setcap", "cap_net_raw=ep", str(helper)], check=True)
    result = subprocess.check_output([shutil.which("getcap") or "/usr/sbin/getcap", str(helper)], text=True)
    if result.strip() != f"{helper} cap_net_raw=ep":
        raise ValueError("CAP_NET_RAW verification failed; active operations unavailable")


def disable_capability(helper):
    try:
        os.getxattr(helper, "security.capability")
        os.removexattr(helper, "security.capability")
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise


def installed_prefix(script):
    return Path(script).resolve().parents[3]


def install(payload, prefix, active):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    previous = read_manifest(prefix)
    destinations = previous["links"] if previous else links(prefix)
    for relative in destinations:
        entry = prefix / relative
        safe_parents(entry.parent)
        if previous is None and os.path.lexists(entry):
            raise ValueError(f"foreign destination refused: {entry}")
    base = prefix / "share/l2solver"
    base.parent.mkdir(parents=True, exist_ok=True)
    # A private generation is never runnable through PATH before the final switch
    staging = Path(tempfile.mkdtemp(prefix=".l2solver-", dir=base.parent))
    created_links = []
    generation_path = None
    published = False
    reactivated = None
    try:
        for name in FILES:
            source = Path(__file__) if name == "l2solver-uninstall" else payload / name
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"invalid payload file: {source}")
            destination = staging / name
            shutil.copyfile(source, destination)
            destination.chmod(0o755 if name in (*BINARIES, "l2solver-uninstall") else 0o644)
            with destination.open("rb") as stream:
                os.fsync(stream.fileno())
        hashes = {name: digest(staging / name) for name in FILES}
        identity = hashlib.sha256(json.dumps([hashes, active], sort_keys=True).encode()).hexdigest()
        existing = previous and identity in previous["generations"]
        if existing:
            shutil.rmtree(staging)
            selected = base / identity
        else:
            if active:
                enable_capability(staging / "l2solver-active-helper")
            staging.chmod(0o755)
            base.mkdir(mode=0o755, exist_ok=True)
            generation_path = base / identity
            staging.rename(generation_path)
            selected = generation_path
        if existing and active:
            if os.readlink(base / "current") != identity:
                reactivated = selected / "l2solver-active-helper"
            enable_capability(selected / "l2solver-active-helper")
        elif not active:
            disable_capability(selected / "l2solver-active-helper")
        data = {"schema": 1, "links": destinations, "generations": dict(previous["generations"]) if previous else {}}
        data["generations"][identity] = hashes
        for relative, target in destinations.items():
            entry = prefix / relative
            entry.parent.mkdir(parents=True, exist_ok=True)
            if previous is None:
                entry.symlink_to(target)
                created_links.append(entry)
        # Journal all owned generations before changing the single active pointer
        write_manifest(base, data)
        (base / ".current-new").symlink_to(identity)
        os.replace(base / ".current-new", base / "current")
        published = True
        # Retain old byte sets for running clients, but revoke their packet authority
        if previous:
            for generation in previous["generations"]:
                if generation != identity:
                    disable_capability(base / generation / "l2solver-active-helper")
        directory_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if not published:
            # A failed switch must not leave an older, unpublished helper privileged
            if reactivated is not None:
                disable_capability(reactivated)
            (base / ".current-new").unlink(missing_ok=True)
            (base / ".manifest-new").unlink(missing_ok=True)
            if previous:
                write_manifest(base, previous)
            else:
                (base / "manifest.json").unlink(missing_ok=True)
            for entry in created_links:
                entry.unlink()
            if generation_path is not None:
                disable_capability(generation_path / "l2solver-active-helper")
                shutil.rmtree(generation_path)
            if not previous and base.exists():
                base.rmdir()
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def uninstall(prefix):
    safe_parents(prefix)
    data = read_manifest(prefix)
    if data is None:
        raise ValueError("no recognized installation")
    base = prefix / "share/l2solver"
    # Revoke authority even if another process holds an open helper file
    for generation in data["generations"]:
        disable_capability(base / generation / "l2solver-active-helper")
    # Validate everything before removing any command or documentation
    for relative in data["links"]:
        (prefix / relative).unlink()
    (base / "current").unlink()
    for generation in data["generations"]:
        for name in FILES:
            (base / generation / name).unlink()
        (base / generation).rmdir()
    (base / "manifest.json").unlink()
    base.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    installed = Path(sys.argv[0]).name == "l2solver-uninstall"
    parser.add_argument("--prefix", type=Path, default=installed_prefix(sys.argv[0]) if installed else Path("/usr/local"))
    parser.add_argument("--uninstall", action="store_true", default=installed)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--enable-active", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("the publication/uninstall step requires root; run scripts/install.sh as an ordinary user")
    if not args.prefix.is_absolute() or args.prefix == Path("/"):
        parser.error("prefix must be an absolute local installation directory")
    # The shared lock lives outside the tree so uninstall cannot unlink a held lock
    safe_parents(args.prefix)
    args.prefix.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.prefix, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.check:
            previous = read_manifest(args.prefix)
            if previous is None:
                for relative in links(args.prefix):
                    safe_parents((args.prefix / relative).parent)
                    if os.path.lexists(args.prefix / relative):
                        raise ValueError(f"foreign destination: {args.prefix / relative}")
        elif args.uninstall:
            uninstall(args.prefix)
        elif args.payload:
            install(args.payload, args.prefix, args.enable_active)
        else:
            parser.error("--payload is required for installation")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation refused: {error}")
