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
COMPLETION_NAMES = {"bash": "l2solver", "zsh": "_l2solver", "fish": "l2solver.fish"}
COMPLETION_CANDIDATES = {
    "bash": ("share/bash-completion/completions", "etc/bash_completion.d"),
    "zsh": ("share/zsh/site-functions", "share/zsh/functions/Completion"),
    "fish": ("share/fish/vendor_completions.d", "share/fish/completions"),
}


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


def completion_directory(value):
    # Accept only normalized paths beneath the protected prefix
    path = Path(value)
    if (path.is_absolute() or str(path) != value or len(path.parts) < 2
            or path.parts[0] not in ("share", "etc") or ".." in path.parts
            or path.parts[:2] == ("share", "l2solver")):
        raise ValueError(f"unsafe completion directory: {value}")
    return str(path)


def links(prefix, completion_dirs=None):
    result = {f"bin/{name}": f"../share/l2solver/current/{name}" for name in (*BINARIES, "l2solver-uninstall")}
    if completion_dirs is None:
        # Preserve the original fallback for calls without discovery information
        completion_dirs = {
            shell: next((item for item in choices if (prefix / item).is_dir()), choices[0])
            for shell, choices in COMPLETION_CANDIDATES.items()
        }
    if set(completion_dirs) != set(COMPLETION_NAMES):
        raise ValueError("completion directories must name bash, zsh and fish")
    for shell, name in COMPLETION_NAMES.items():
        directory = completion_directory(completion_dirs[shell])
        destination = f"{directory}/{name}"
        result[destination] = os.path.relpath(prefix / "share/l2solver/current" / shell, (prefix / destination).parent)
    return result


def validate_links(prefix, recorded):
    if not isinstance(recorded, dict):
        raise ValueError("unsafe manifest links")
    binaries = {f"bin/{name}" for name in (*BINARIES, "l2solver-uninstall")}
    completion_dirs = {}
    for relative in recorded:
        if not isinstance(relative, str):
            raise ValueError("unsafe manifest link")
        if relative in binaries:
            continue
        path = Path(relative)
        shell = next((shell for shell, name in COMPLETION_NAMES.items() if path.name == name), None)
        if shell is None or shell in completion_dirs or str(path) != relative:
            raise ValueError(f"unsafe manifest link: {relative}")
        completion_dirs[shell] = completion_directory(str(path.parent))
    # The recorded destinations remain authoritative even when search paths change
    if recorded != links(prefix, completion_dirs):
        raise ValueError("unsafe or incomplete manifest links")


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
    validate_links(prefix, data["links"])
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
    result = subprocess.check_output(["/usr/sbin/getcap" if Path("/usr/sbin/getcap").exists() else "/usr/bin/getcap", str(helper)], text=True)
    if result.strip() != f"{helper} cap_net_raw=ep":
        raise ValueError("CAP_NET_RAW verification failed; active operations unavailable")


def read_capability(helper):
    try:
        return os.getxattr(helper, "security.capability")
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise
        return None


def disable_capability(helper):
    if read_capability(helper) is not None:
        os.removexattr(helper, "security.capability")


def restore_capability(helper, value):
    if read_capability(helper) == value:
        return
    if value is None:
        disable_capability(helper)
    else:
        os.setxattr(helper, "security.capability", value)


def installed_prefix(script):
    return Path(script).resolve().parents[3]


def parse_completion_dirs(values):
    if not values:
        return None
    selected = {}
    for value in values:
        shell, separator, directory = value.partition("=")
        if not separator or shell not in COMPLETION_NAMES or shell in selected:
            raise ValueError("invalid completion directory selection")
        selected[shell] = completion_directory(directory)
    if set(selected) != set(COMPLETION_NAMES):
        raise ValueError("completion directories must name bash, zsh and fish")
    return selected


def install(payload, prefix, active, completion_dirs=None):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    previous = read_manifest(prefix)
    destinations = previous["links"] if previous else links(prefix, completion_dirs)
    for relative in destinations:
        entry = prefix / relative
        safe_parents(entry.parent)
        if previous is None and os.path.lexists(entry):
            raise ValueError(f"foreign destination refused: {entry}")
    base = prefix / "share/l2solver"
    old_current = os.readlink(base / "current") if previous else None
    base.parent.mkdir(parents=True, exist_ok=True)
    # A private generation is never runnable through PATH before the final switch
    staging = Path(tempfile.mkdtemp(prefix=".l2solver-", dir=base.parent))
    created_links = []
    generation_path = None
    published = False
    switch_attempted = False
    new_capability_attempted = False
    reopen_started = False
    changed_capabilities = []
    old_capabilities = {}
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
            base.mkdir(mode=0o755, exist_ok=True)
            generation_path = base / identity
            staging.rename(generation_path)
            selected = generation_path
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
        if previous:
            old_capabilities = {
                base / generation / "l2solver-active-helper": read_capability(base / generation / "l2solver-active-helper")
                for generation in previous["generations"]
            }
            # Revoke older helpers before publication so a failed revoke cannot leave an extra privileged helper
            for helper, saved in old_capabilities.items():
                if helper.parent != selected:
                    changed_capabilities.append((helper, saved))
                    disable_capability(helper)
        helper = selected / "l2solver-active-helper"
        if existing:
            # Setting a capability can succeed before its verification fails
            changed_capabilities.append((helper, old_capabilities[helper]))
        if active:
            new_capability_attempted = generation_path is not None
            enable_capability(helper)
        elif existing:
            # A copied file has no capability, but a retained generation may
            disable_capability(helper)
        if stat.S_IMODE(selected.stat().st_mode) == 0o700:
            # Open a new or quarantined generation only after its policy succeeds
            reopen_started = True
            selected.chmod(0o755)
        if old_current != identity:
            (base / ".current-new").symlink_to(identity)
            switch_attempted = True
            os.replace(base / ".current-new", base / "current")
        published = True
        directory_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException as error:
        if not published and switch_attempted:
            # An interrupt can arrive after the atomic rename but before its return
            try:
                actual_current = os.readlink(base / "current")
            except FileNotFoundError:
                actual_current = None
            except OSError as failure:
                raise ValueError(f"{error}; publication outcome unknown: {failure}") from error
            if actual_current == identity:
                published = True
            elif actual_current != old_current:
                raise ValueError(f"{error}; publication outcome unknown: unexpected current generation") from error
        if not published:
            rollback_errors = []
            retain_generation = False
            if generation_path is not None and new_capability_attempted:
                try:
                    disable_capability(generation_path / "l2solver-active-helper")
                except OSError as failure:
                    retain_generation = True
                    rollback_errors.append(f"could not revoke unpublished helper {helper}: {failure}")
                    try:
                        if stat.S_IMODE(generation_path.stat().st_mode) != 0o700:
                            generation_path.chmod(0o700)
                    except OSError as quarantine_failure:
                        rollback_errors.append(f"could not restrict {generation_path}: {quarantine_failure}")
            restricted = True
            if reopen_started and existing:
                try:
                    if stat.S_IMODE(selected.stat().st_mode) != 0o700:
                        selected.chmod(0o700)
                except OSError as failure:
                    restricted = False
                    rollback_errors.append(f"could not restrict {selected}: {failure}")
            # Restore the exact former xattrs if publication did not take place
            for helper, saved in reversed(changed_capabilities):
                try:
                    if not restricted and helper.parent == selected:
                        # Avoid restoring authority to a generation that stayed accessible
                        disable_capability(helper)
                        rollback_errors.append(f"former capability not restored for {helper}")
                    else:
                        restore_capability(helper, saved)
                except OSError as failure:
                    rollback_errors.append(f"could not restore {helper}: {failure}")
            for temporary in (base / ".current-new", base / ".manifest-new"):
                try:
                    temporary.unlink(missing_ok=True)
                except OSError as failure:
                    if not retain_generation:
                        raise
                    rollback_errors.append(f"could not remove {temporary}: {failure}")
            if retain_generation:
                raise ValueError(
                    f"{error}; rollback incomplete: {'; '.join(rollback_errors)}; "
                    f"generation retained at {generation_path}; administrator inspection required"
                ) from error
            if previous:
                write_manifest(base, previous)
            else:
                (base / "manifest.json").unlink(missing_ok=True)
            for entry in created_links:
                entry.unlink()
            if generation_path is not None:
                shutil.rmtree(generation_path)
            if not previous and base.exists():
                base.rmdir()
            if rollback_errors:
                raise ValueError(f"{error}; rollback incomplete: {'; '.join(rollback_errors)}") from error
        elif isinstance(error, OSError):
            raise ValueError(f"new installation is active, but publication or final filesystem sync failed: {error}") from error
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
    parser.add_argument("--completion-dir", action="append", default=[], metavar="SHELL=PATH")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("the publication/uninstall step requires root; run scripts/install.sh as an ordinary user")
    if not args.prefix.is_absolute():
        parser.error("prefix must be an absolute local installation directory")
    args.prefix = Path(os.path.abspath(args.prefix))
    if args.prefix == Path("/"):
        parser.error("prefix must be an absolute local installation directory")
    completion_dirs = parse_completion_dirs(args.completion_dir)
    # The shared lock lives outside the tree so uninstall cannot unlink a held lock
    safe_parents(args.prefix)
    args.prefix.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.prefix, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.check:
            previous = read_manifest(args.prefix)
            if previous is None:
                for relative in links(args.prefix, completion_dirs):
                    safe_parents((args.prefix / relative).parent)
                    if os.path.lexists(args.prefix / relative):
                        raise ValueError(f"foreign destination: {args.prefix / relative}")
            elif completion_dirs is not None and previous["links"] != links(args.prefix, completion_dirs):
                print("warning: retaining existing completion destinations from the protected manifest", file=sys.stderr)
        elif args.uninstall:
            uninstall(args.prefix)
        elif args.payload:
            install(args.payload, args.prefix, args.enable_active, completion_dirs)
        else:
            parser.error("--payload is required for installation")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation refused: {error}")
