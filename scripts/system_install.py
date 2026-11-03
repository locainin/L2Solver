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

MAX_GENERATIONS = 16

BINARIES = ("l2solver", "l2solver-active", "l2solver-active-helper")
FILES = (*BINARIES, "l2solver-uninstall", "bash", "zsh", "fish", "NOTICE-JEMALLOC.txt", "receipt.json")
# Keep the original schema-1 file set fixed across later payload changes
LEGACY_FILES = frozenset((
    "l2solver", "l2solver-active", "l2solver-active-helper", "l2solver-uninstall",
    "bash", "zsh", "fish", "README.md", "install.md", "NOTICE-JEMALLOC.txt", "receipt.json",
))
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


def validate_manifest(prefix, data):
    if (not isinstance(data, dict) or set(data) != {"schema", "links", "generations"}
            or data["schema"] != 1 or not isinstance(data["generations"], dict)
            or not data["generations"]):
        raise ValueError("unrecognized installation manifest")
    validate_links(prefix, data["links"])
    for generation, hashes in data["generations"].items():
        # Earlier schema-1 generations included two extra files
        if (not isinstance(generation, str) or not re.fullmatch(r"[0-9a-f]{64}", generation)
                or not isinstance(hashes, dict)
                or frozenset(hashes) not in (frozenset(FILES), LEGACY_FILES)
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in hashes.values())):
            raise ValueError("unsafe manifest generation")


def regular_file(path, expected=None, mode=None):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
            or (expected is not None and digest(path) != expected)):
        raise ValueError(f"modified installed file: {path}")


def private_manifest(path):
    regular_file(path)
    if stat.S_IMODE(path.lstat().st_mode) & 0o077:
        raise ValueError("unsafe installation manifest")


def validate_generation(base, generation, hashes, *, partial=False):
    directory = base / generation
    if not os.path.lexists(directory):
        if partial:
            return
        raise ValueError(f"missing installation directory: {directory}")
    safe_parents(directory)
    names = {item.name for item in directory.iterdir()}
    if not names <= set(hashes) or (not partial and names != set(hashes)):
        raise ValueError(f"modified installation directory: {directory}")
    for name in names:
        mode = 0o755 if name in (*BINARIES, "l2solver-uninstall") else 0o644
        regular_file(directory / name, hashes[name], mode)


def read_manifest_structure(prefix):
    base = prefix / "share/l2solver"
    path = base / "manifest.json"
    if not os.path.lexists(path):
        if os.path.lexists(base):
            raise ValueError(f"unrecognized installation tree: {base}")
        return None
    safe_parents(base)
    private_manifest(path)
    data = json.loads(path.read_text())
    validate_manifest(prefix, data)
    return data


def read_manifest(prefix):
    base = prefix / "share/l2solver"
    data = read_manifest_structure(prefix)
    if data is None:
        return None
    for generation, hashes in data["generations"].items():
        validate_generation(base, generation, hashes)
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


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_directory(path):
    if os.path.lexists(path):
        safe_parents(path)
        return
    ensure_directory(path.parent)
    try:
        path.mkdir(mode=0o755)
    except FileExistsError:
        pass
    safe_parents(path)
    # Persist each new component in its own parent
    sync_directory(path.parent)


def open_directory(path):
    parts = Path(os.path.abspath(path)).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(parts[0], flags)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def sync_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_private_file(path):
    if os.path.lexists(path):
        regular_file(path, mode=0o600)
        path.unlink()


def write_json(path, temporary, data):
    # The exclusive temporary file is private even before its first write
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def copy_payload(source, destination, mode, source_directory):
    if source.is_symlink():
        raise ValueError(f"invalid payload file: {source}")
    # Recheck the opened inode so a changed source cannot redirect a privileged copy
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_directory)
    except OSError as error:
        raise ValueError(f"invalid payload file: {source}: {error}") from error
    with os.fdopen(fd, "rb") as source_stream:
        if not stat.S_ISREG(os.fstat(source_stream.fileno()).st_mode):
            raise ValueError(f"invalid payload file: {source}")
        target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(target_fd, "wb") as target:
            shutil.copyfileobj(source_stream, target)
            os.fchmod(target.fileno(), mode)
            target.flush()
            os.fsync(target.fileno())


def write_manifest(base, data):
    write_json(base / "manifest.json", base / ".manifest-new", data)


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
    resolved = Path(script).resolve()
    # During removal this command is an independent file in the bin directory
    if resolved.parent.name == "bin":
        return resolved.parent.parent
    return resolved.parents[3]


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


def transaction_paths(prefix):
    share = prefix / "share"
    return share / ".l2solver-transaction", share / ".l2solver-transaction-new", share / ".l2solver-stage"


def validate_transaction(prefix, data):
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("unsafe installation transaction")
    operation = data.get("op")
    common = {"schema", "op", "phase", "previous", "current"}
    extra = {
        "install": {"links", "capabilities", "modes", "selected", "desired", "active"},
        "uninstall": {"uninstaller"},
        "retire": set(),
        "quarantine": {"target"},
    }
    if operation not in extra or set(data) != common | extra[operation]:
        raise ValueError("unsafe installation transaction")
    previous = data["previous"]
    if previous is not None:
        validate_manifest(prefix, previous)
        if data["current"] not in previous["generations"]:
            raise ValueError("unsafe transaction current generation")
    elif operation != "install" or data["current"] is not None:
        raise ValueError("unsafe transaction previous generation")
    if operation == "install":
        if data["phase"] not in ("preparing", "prepared", "committed") or not isinstance(data["active"], bool):
            raise ValueError("unsafe installation transaction phase")
        validate_links(prefix, data["links"])
        if previous and data["links"] != previous["links"]:
            raise ValueError("unsafe installation transaction links")
        generations = set(previous["generations"]) if previous else set()
        if (not isinstance(data["capabilities"], dict) or set(data["capabilities"]) != generations
                or not isinstance(data["modes"], dict) or set(data["modes"]) != generations):
            raise ValueError("unsafe installation transaction capabilities")
        for value in data["capabilities"].values():
            if value is not None:
                if not isinstance(value, str) or len(value) > 256:
                    raise ValueError("unsafe installation capability")
                try:
                    bytes.fromhex(value)
                except ValueError as error:
                    raise ValueError("unsafe installation capability") from error
        if any(not isinstance(mode, int) or mode < 0 or mode > 0o7777 for mode in data["modes"].values()):
            raise ValueError("unsafe installation directory mode")
        if data["phase"] == "preparing":
            if data["selected"] is not None or data["desired"] is not None:
                raise ValueError("unsafe preparing transaction")
        else:
            desired, selected = data["desired"], data["selected"]
            validate_manifest(prefix, desired)
            if (selected not in desired["generations"] or desired["links"] != data["links"]
                    or set(desired["generations"]) != generations | {selected}
                    or any(desired["generations"][key] != previous["generations"][key] for key in generations)):
                raise ValueError("unsafe prepared transaction")
            expected = hashlib.sha256(json.dumps([desired["generations"][selected], data["active"]], sort_keys=True).encode()).hexdigest()
            if selected != expected or (data["phase"] == "committed" and selected != data["current"]):
                raise ValueError("unsafe selected generation")
    elif data["phase"] not in ("prepared", "revoked"):
        raise ValueError("unsafe removal transaction phase")
    elif operation == "quarantine" and (data["phase"] != "prepared"
            or data["target"] == data["current"] or data["target"] not in previous["generations"]):
        raise ValueError("unsafe quarantine target")
    elif operation == "uninstall" and (not isinstance(data["uninstaller"], str)
                                       or not re.fullmatch(r"[0-9a-f]{64}", data["uninstaller"])):
        raise ValueError("unsafe uninstaller transaction")


def store_transaction(prefix, data):
    path, temporary, _ = transaction_paths(prefix)
    write_json(path, temporary, data)


def discard_transaction(prefix):
    path, temporary, _ = transaction_paths(prefix)
    remove_private_file(temporary)
    path.unlink()
    sync_directory(path.parent)


def cleanup_stage(stage):
    if not os.path.lexists(stage):
        return
    safe_parents(stage)
    for entry in stage.iterdir():
        if entry.name not in FILES:
            raise ValueError(f"unrecognized staged file: {entry}")
        regular_file(entry)
        entry.unlink()
    sync_directory(stage)
    stage.rmdir()
    sync_directory(stage.parent)


def cleanup_temporary(base, selected):
    remove_private_file(base / ".manifest-new")
    pointer = base / ".current-new"
    if os.path.lexists(pointer):
        if not pointer.is_symlink() or os.readlink(pointer) != selected:
            raise ValueError("unsafe temporary current pointer")
        pointer.unlink()


def remove_generation(base, generation, hashes):
    directory = base / generation
    validate_generation(base, generation, hashes, partial=True)
    if not os.path.lexists(directory):
        return
    for name in hashes:
        entry = directory / name
        if os.path.lexists(entry):
            entry.unlink()
    sync_directory(directory)
    directory.rmdir()
    sync_directory(base)


def actual_current(base):
    path = base / "current"
    if not os.path.lexists(path):
        return None
    if not path.is_symlink():
        raise ValueError("unsafe current generation")
    return os.readlink(path)


def validate_owned_tree(prefix, previous, current, *, partial, selected=None, desired=None, preserve_current=False):
    base = prefix / "share/l2solver"
    if not os.path.lexists(base):
        if partial and not preserve_current:
            return
        raise ValueError("missing installation tree")
    safe_parents(base)
    generations = dict(previous["generations"]) if previous else {}
    if selected and desired:
        generations[selected] = desired["generations"][selected]
    allowed = set(generations) | {"current", "manifest.json", ".manifest-new", ".current-new"}
    if not {item.name for item in base.iterdir()} <= allowed:
        raise ValueError("unrecognized files in installation tree")
    for generation, hashes in generations.items():
        allow_missing = ((partial and (not preserve_current or generation != current))
                         or (selected == generation and generation not in (previous or {}).get("generations", {})))
        validate_generation(base, generation, hashes, partial=allow_missing)
    actual = actual_current(base)
    if actual is not None and actual not in {current, selected}:
        raise ValueError("unsafe current generation")
    if (not partial or preserve_current) and current is not None and actual != current:
        raise ValueError("unsafe current generation")
    manifest = base / "manifest.json"
    if os.path.lexists(manifest):
        private_manifest(manifest)
        stored = json.loads(manifest.read_text())
        if stored != previous and stored != desired:
            raise ValueError("modified installation manifest")
    elif (not partial or preserve_current) and previous is not None:
        raise ValueError("missing installation manifest")


def validate_owned_links(prefix, links_owned, *, partial, standalone=None):
    for relative, target in links_owned.items():
        entry = prefix / relative
        safe_parents(entry.parent)
        if not os.path.lexists(entry):
            if partial:
                continue
            raise ValueError(f"missing installation link: {entry}")
        if entry.is_symlink() and os.readlink(entry) == target:
            continue
        if relative == "bin/l2solver-uninstall" and standalone is not None:
            regular_file(entry, standalone, 0o755)
            continue
        raise ValueError(f"modified installation link: {entry}")


def rollback_install(prefix, data):
    base = prefix / "share/l2solver"
    previous, selected, desired = data["previous"], data["selected"], data["desired"]
    _, _, stage = transaction_paths(prefix)
    if data["phase"] == "preparing":
        cleanup_stage(stage)
        discard_transaction(prefix)
        return
    validate_owned_tree(prefix, previous, data["current"], partial=previous is None, selected=selected, desired=desired)
    validate_owned_links(prefix, data["links"], partial=previous is None)
    if os.path.lexists(base):
        cleanup_temporary(base, selected)
    new_generation = selected not in (previous or {}).get("generations", {})
    helper = base / selected / "l2solver-active-helper"
    revocation_error = None
    if new_generation and os.path.lexists(helper):
        try:
            disable_capability(helper)
            sync_file(helper)
        except OSError as error:
            # Keep an unrevoked helper out of reach and retain its ownership record
            try:
                (base / selected).chmod(0o700)
                sync_directory(base / selected)
            except OSError as failure:
                raise ValueError(f"could not revoke unpublished helper {helper}: {error}; could not restrict {helper.parent}: {failure}") from error
            revocation_error = error
    if previous:
        for generation in previous["generations"]:
            directory = base / generation
            mode = data["modes"][generation]
            if stat.S_IMODE(directory.stat().st_mode) != mode:
                try:
                    directory.chmod(mode)
                    sync_directory(directory)
                except OSError as error:
                    if generation == selected:
                        disable_capability(directory / "l2solver-active-helper")
                        raise ValueError(f"could not restrict {directory}: {error}; former capability not restored") from error
                    raise
            saved = data["capabilities"][generation]
            restore_capability(directory / "l2solver-active-helper", bytes.fromhex(saved) if saved is not None else None)
            sync_file(directory / "l2solver-active-helper")
    if revocation_error is not None:
        raise ValueError(f"could not revoke unpublished helper {helper}: {revocation_error}; generation retained at {helper.parent}") from revocation_error
    if previous:
        # The journal remains authoritative until every rollback step is durable
        write_manifest(base, previous)
    elif os.path.lexists(base / "manifest.json"):
        (base / "manifest.json").unlink()
    if previous is None:
        for relative, target in data["links"].items():
            entry = prefix / relative
            if os.path.lexists(entry):
                if not entry.is_symlink() or os.readlink(entry) != target:
                    raise ValueError(f"modified installation link: {entry}")
                entry.unlink()
                sync_directory(entry.parent)
    if new_generation and os.path.lexists(base):
        remove_generation(base, selected, desired["generations"][selected])
    cleanup_stage(stage)
    if previous is None and os.path.lexists(base):
        sync_directory(base)
        base.rmdir()
        sync_directory(base.parent)
    discard_transaction(prefix)


def finish_install(prefix, data):
    base = prefix / "share/l2solver"
    cleanup_temporary(base, data["selected"])
    read_manifest(prefix)
    selected = base / data["selected"]
    if stat.S_IMODE(selected.stat().st_mode) == 0o700:
        selected.chmod(0o755)
        sync_directory(selected)
    cleanup_stage(transaction_paths(prefix)[2])
    sync_directory(base)
    discard_transaction(prefix)


def prepare_uninstaller(prefix, data):
    entry = prefix / "bin/l2solver-uninstall"
    temporary = entry.parent / ".l2solver-uninstall-new"
    if os.path.lexists(entry) and not entry.is_symlink():
        regular_file(entry, data["uninstaller"], 0o755)
        if os.path.lexists(temporary):
            regular_file(temporary)
            temporary.unlink()
        return
    if os.path.lexists(temporary):
        regular_file(temporary)
        temporary.unlink()
    # A standalone copy remains callable after the current pointer is removed
    shutil.copyfile(Path(__file__), temporary)
    temporary.chmod(0o755)
    sync_file(temporary)
    regular_file(temporary, data["uninstaller"], 0o755)
    os.replace(temporary, entry)
    sync_directory(entry.parent)


def finish_removal(prefix, data):
    base = prefix / "share/l2solver"
    previous, current = data["previous"], data["current"]
    removing = set(previous["generations"])
    if data["op"] == "retire":
        removing.remove(current)
    partial = data["phase"] == "revoked"
    desired = None
    if data["op"] == "retire":
        desired = {"schema": 1, "links": previous["links"], "generations": {current: previous["generations"][current]}}
    validate_owned_tree(prefix, previous, current, partial=partial, desired=desired,
                        preserve_current=data["op"] == "retire")
    validate_owned_links(prefix, previous["links"], partial=partial and data["op"] == "uninstall",
                         standalone=data.get("uninstaller"))
    if data["op"] == "uninstall":
        entry = prefix / "bin/l2solver-uninstall"
        if not os.path.lexists(base) and not os.path.lexists(entry):
            discard_transaction(prefix)
            return
        prepare_uninstaller(prefix, data)
    # Never unlink a helper until all recorded helpers have been revoked
    for generation in removing:
        helper = base / generation / "l2solver-active-helper"
        if os.path.lexists(helper):
            disable_capability(helper)
            sync_file(helper)
        elif not partial:
            raise ValueError(f"missing installed helper: {helper}")
    if not partial:
        data["phase"] = "revoked"
        store_transaction(prefix, data)
    if data["op"] == "uninstall":
        for relative in previous["links"]:
            if relative == "bin/l2solver-uninstall":
                continue
            entry = prefix / relative
            if os.path.lexists(entry):
                entry.unlink()
                sync_directory(entry.parent)
        pointer = base / "current"
        if os.path.lexists(pointer):
            pointer.unlink()
            sync_directory(base)
    for generation in removing:
        remove_generation(base, generation, previous["generations"][generation])
    if data["op"] == "retire":
        if os.path.lexists(base / ".manifest-new"):
            remove_private_file(base / ".manifest-new")
        write_manifest(base, desired)
    elif os.path.lexists(base):
        manifest = base / "manifest.json"
        if os.path.lexists(manifest):
            manifest.unlink()
        sync_directory(base)
        base.rmdir()
        sync_directory(base.parent)
    if data["op"] == "uninstall":
        entry = prefix / "bin/l2solver-uninstall"
        if os.path.lexists(entry):
            regular_file(entry, data["uninstaller"], 0o755)
        # The standalone command is the last owned path removed
        discard_transaction(prefix)
        if os.path.lexists(entry):
            entry.unlink()
            sync_directory(entry.parent)
        return
    discard_transaction(prefix)


def quarantine_generations(prefix):
    directory = prefix / "share/.l2solver-quarantine"
    if not os.path.lexists(directory):
        return set()
    safe_parents(directory)
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ValueError("unsafe quarantine directory")
    generations = set()
    for entry in directory.iterdir():
        if not re.fullmatch(r"[0-9a-f]{64}", entry.name):
            raise ValueError(f"unsafe quarantine entry: {entry}")
        safe_parents(entry)
        if stat.S_IMODE(entry.stat().st_mode) != 0o700:
            raise ValueError(f"unsafe quarantine entry: {entry}")
        generations.add(entry.name)
    return generations


def validate_quarantine_tree(prefix, data):
    base = prefix / "share/l2solver"
    previous, current, target = data["previous"], data["current"], data["target"]
    safe_parents(base)
    allowed = set(previous["generations"]) | {"current", "manifest.json", ".manifest-new"}
    if not {item.name for item in base.iterdir()} <= allowed:
        raise ValueError("unrecognized files in installation tree")
    if actual_current(base) != current:
        raise ValueError("unsafe current generation")
    for generation, hashes in previous["generations"].items():
        if generation != target:
            validate_generation(base, generation, hashes)
    validate_owned_links(prefix, previous["links"], partial=False)
    desired = {"schema": 1, "links": previous["links"],
               "generations": {key: value for key, value in previous["generations"].items() if key != target}}
    manifest = base / "manifest.json"
    private_manifest(manifest)
    if json.loads(manifest.read_text()) not in (previous, desired):
        raise ValueError("modified installation manifest")
    return desired


def finish_quarantine(prefix, data):
    base = prefix / "share/l2solver"
    quarantine = prefix / "share/.l2solver-quarantine"
    source, destination = base / data["target"], quarantine / data["target"]
    desired = validate_quarantine_tree(prefix, data)
    source_exists, destination_exists = os.path.lexists(source), os.path.lexists(destination)
    if source_exists == destination_exists:
        raise ValueError("unsafe quarantine source or destination")
    if source_exists:
        safe_parents(source)
        helper = source / "l2solver-active-helper"
        regular_file(helper)
        # Close the damaged directory before touching its helper authority
        source.chmod(0o700)
        sync_directory(source)
        disable_capability(helper)
        sync_file(helper)
        if not os.path.lexists(quarantine):
            quarantine.mkdir(mode=0o700)
            sync_directory(quarantine.parent)
        quarantine_generations(prefix)
        source.rename(destination)
        # Persist the destination before the source directory records its removal
        sync_directory(quarantine)
        sync_directory(base)
    else:
        quarantine_generations(prefix)
        helper = destination / "l2solver-active-helper"
        regular_file(helper)
        disable_capability(helper)
        sync_file(helper)
    remove_private_file(base / ".manifest-new")
    write_manifest(base, desired)
    discard_transaction(prefix)


def recover(prefix, *, resume=()):
    prefix = Path(os.path.abspath(prefix))
    path, temporary, _ = transaction_paths(prefix)
    safe_parents(path.parent)
    if not os.path.lexists(path):
        if os.path.lexists(temporary):
            # No action can start before the initial journal is published
            # Check the record without blocking quarantine of a damaged generation
            read_manifest_structure(prefix)
            remove_private_file(temporary)
            sync_directory(temporary.parent)
        return None
    regular_file(path, mode=0o600)
    data = json.loads(path.read_text())
    validate_transaction(prefix, data)
    if data["op"] in ("uninstall", "retire", "quarantine") and data["op"] not in resume:
        action = {"uninstall": "--uninstall", "retire": "--retire-inactive",
                  "quarantine": f"--quarantine-inactive {data.get('target', '')}"}[data["op"]]
        raise ValueError(f"interrupted removal requires all clients to stop; retry {action}")
    remove_private_file(temporary)
    if data["op"] == "install":
        if data["phase"] in ("prepared", "committed"):
            actual = actual_current(prefix / "share/l2solver")
            if actual == data["selected"] and (actual != data["current"] or data["phase"] == "committed"):
                finish_install(prefix, data)
            elif actual != data["current"]:
                raise ValueError("publication outcome unknown: unexpected current generation")
            else:
                rollback_install(prefix, data)
        else:
            rollback_install(prefix, data)
    elif data["op"] == "quarantine":
        finish_quarantine(prefix, data)
    else:
        finish_removal(prefix, data)
    return data["op"]


def install(payload, prefix, active, completion_dirs=None):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    recover(prefix)
    previous = read_manifest(prefix)
    destinations = previous["links"] if previous else links(prefix, completion_dirs)
    for relative in destinations:
        entry = prefix / relative
        safe_parents(entry.parent)
        if previous is None and os.path.lexists(entry):
            raise ValueError(f"foreign destination refused: {entry}")
    base = prefix / "share/l2solver"
    old_current = os.readlink(base / "current") if previous else None
    ensure_directory(base.parent)
    path, temporary, staging = transaction_paths(prefix)
    if os.path.lexists(path) or os.path.lexists(temporary) or os.path.lexists(staging):
        raise ValueError("foreign transaction or staging path refused")
    capabilities = {}
    modes = {}
    if previous:
        for generation in previous["generations"]:
            directory = base / generation
            value = read_capability(directory / "l2solver-active-helper")
            capabilities[generation] = value.hex() if value is not None else None
            modes[generation] = stat.S_IMODE(directory.stat().st_mode)
    transaction = {"schema": 1, "op": "install", "phase": "preparing", "previous": previous,
                   "current": old_current, "links": destinations, "capabilities": capabilities,
                   "modes": modes, "selected": None, "desired": None, "active": active}
    store_transaction(prefix, transaction)
    switched = False
    payload_fd = publisher_fd = None
    try:
        # Pin each source directory before copying any files
        payload_fd = open_directory(payload)
        publisher_fd = open_directory(Path(__file__).parent)
        staging.mkdir(mode=0o700)
        sync_directory(staging.parent)
        for name in FILES:
            source = Path(__file__) if name == "l2solver-uninstall" else payload / name
            destination = staging / name
            source_fd = publisher_fd if name == "l2solver-uninstall" else payload_fd
            copy_payload(source, destination, 0o755 if name in (*BINARIES, "l2solver-uninstall") else 0o644, source_fd)
        sync_directory(staging)
        hashes = {name: digest(staging / name) for name in FILES}
        identity = hashlib.sha256(json.dumps([hashes, active], sort_keys=True).encode()).hexdigest()
        existing = previous is not None and identity in previous["generations"]
        if active and existing and old_current != identity:
            # A retained inode may still be open in an older client
            raise ValueError("active re-selection requires stopping all L2Solver processes; run --retire-inactive and reinstall")
        retained_count = (len(previous["generations"]) if previous else 0) + len(quarantine_generations(prefix))
        if not existing and retained_count >= MAX_GENERATIONS:
            raise ValueError("generation limit reached; stop all L2Solver processes and retire inactive generations")
        desired = {"schema": 1, "links": destinations, "generations": dict(previous["generations"]) if previous else {}}
        desired["generations"][identity] = hashes
        transaction.update(phase="prepared", selected=identity, desired=desired)
        store_transaction(prefix, transaction)
        if existing:
            cleanup_stage(staging)
        else:
            base.mkdir(mode=0o755, exist_ok=True)
            staging.rename(base / identity)
            sync_directory(base)
            sync_directory(base.parent)
        selected = base / identity
        if previous is None:
            for relative, target in destinations.items():
                entry = prefix / relative
                ensure_directory(entry.parent)
                entry.symlink_to(target)
                sync_directory(entry.parent)
        write_manifest(base, desired)
        for generation in capabilities:
            helper = base / generation / "l2solver-active-helper"
            if generation != identity:
                disable_capability(helper)
                sync_file(helper)
        helper = selected / "l2solver-active-helper"
        # New and quarantined generations stay private until the pointer switch
        if active:
            enable_capability(helper)
        elif existing:
            disable_capability(helper)
        sync_file(helper)
        if old_current != identity:
            (base / ".current-new").symlink_to(identity)
            os.replace(base / ".current-new", base / "current")
        switched = True
        sync_directory(base)
        if stat.S_IMODE(selected.stat().st_mode) == 0o700:
            selected.chmod(0o755)
            sync_directory(selected)
        # A same-generation reinstall needs a durable commit marker in place of a pointer switch
        if old_current == identity:
            transaction["phase"] = "committed"
            store_transaction(prefix, transaction)
        discard_transaction(prefix)
    except BaseException as error:
        try:
            actual = actual_current(base)
        except OSError as failure:
            raise ValueError(f"{error}; publication outcome unknown: {failure}") from error
        if switched or (transaction["selected"] is not None and actual == transaction["selected"] and actual != old_current):
            if isinstance(error, OSError):
                raise ValueError(f"new installation is active, but publication or final filesystem sync failed: {error}") from error
            raise
        try:
            recover(prefix)
        except BaseException as failure:
            raise ValueError(f"{error}; rollback incomplete: {failure}") from error
        raise
    finally:
        for fd in (payload_fd, publisher_fd):
            if fd is not None:
                os.close(fd)


def uninstall(prefix):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    recovered = recover(prefix, resume=("uninstall", "retire", "quarantine"))
    data = read_manifest(prefix)
    if data is None:
        if recovered in ("install", "uninstall"):
            return
        entry = prefix / "bin/l2solver-uninstall"
        if os.path.lexists(entry) and Path(__file__).resolve() == entry:
            # A prior uninstall may have stopped just before removing this file
            safe_parents(entry.parent)
            regular_file(entry, mode=0o755)
            entry.unlink()
            sync_directory(entry.parent)
            return
        raise ValueError("no recognized installation")
    current = os.readlink(prefix / "share/l2solver/current")
    temporary = prefix / "bin/.l2solver-uninstall-new"
    if os.path.lexists(temporary):
        raise ValueError("foreign uninstaller staging path refused")
    transaction = {"schema": 1, "op": "uninstall", "phase": "prepared", "previous": data,
                   "current": current, "uninstaller": digest(Path(__file__))}
    store_transaction(prefix, transaction)
    finish_removal(prefix, transaction)


def retire_inactive(prefix):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    recover(prefix, resume=("retire",))
    data = read_manifest(prefix)
    if data is None:
        raise ValueError("no recognized installation")
    current = os.readlink(prefix / "share/l2solver/current")
    if len(data["generations"]) == 1:
        return
    transaction = {"schema": 1, "op": "retire", "phase": "prepared", "previous": data, "current": current}
    store_transaction(prefix, transaction)
    finish_removal(prefix, transaction)


def revoke_active(prefix):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    base = prefix / "share/l2solver"
    data = read_manifest_structure(prefix)
    if data is None:
        raise ValueError("no recognized installation")
    current = actual_current(base)
    if current not in data["generations"]:
        raise ValueError("unsafe current generation")
    helper = base / current / "l2solver-active-helper"
    safe_parents(helper.parent)
    regular_file(helper)
    path, temporary, _ = transaction_paths(prefix)
    if os.path.lexists(path):
        regular_file(path, mode=0o600)
        pending = json.loads(path.read_text())
        validate_transaction(prefix, pending)
        if pending["op"] == "install" and current in pending["capabilities"]:
            # A later rollback must not restore the authority being revoked now
            pending["capabilities"][current] = None
            remove_private_file(temporary)
            store_transaction(prefix, pending)
    disable_capability(helper)
    sync_file(helper)


def quarantine_inactive(prefix, generation):
    prefix = Path(os.path.abspath(prefix))
    safe_parents(prefix)
    path, _, _ = transaction_paths(prefix)
    if os.path.lexists(path):
        regular_file(path, mode=0o600)
        pending = json.loads(path.read_text())
        validate_transaction(prefix, pending)
        if pending["op"] == "quarantine" and pending["target"] != generation:
            raise ValueError("interrupted quarantine requires its original generation")
    recovered = recover(prefix, resume=("quarantine",))
    if recovered == "quarantine":
        return
    previous = read_manifest_structure(prefix)
    if previous is None:
        raise ValueError("no recognized installation")
    current = actual_current(prefix / "share/l2solver")
    if generation not in previous["generations"] or generation == current:
        raise ValueError("quarantine requires a recorded inactive generation")
    transaction = {"schema": 1, "op": "quarantine", "phase": "prepared", "previous": previous,
                   "current": current, "target": generation}
    validate_transaction(prefix, transaction)
    validate_quarantine_tree(prefix, transaction)
    source = prefix / "share/l2solver" / generation
    safe_parents(source)
    regular_file(source / "l2solver-active-helper")
    if generation in quarantine_generations(prefix):
        raise ValueError("quarantine destination already exists")
    store_transaction(prefix, transaction)
    finish_quarantine(prefix, transaction)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            f"At most {MAX_GENERATIONS} installed and quarantined generations are retained; this is a count limit, not a byte limit. "
            "Stop all L2Solver processes before removal, retirement, or quarantine, and repeat the same action after an interruption. "
            "To reactivate a retained older generation, retire inactive generations first, then reinstall it. "
            "Quarantined files are kept in <prefix>/share/.l2solver-quarantine/GENERATION for administrator inspection; "
            "remove a reviewed directory manually to free its slot. "
            "If a first installation was interrupted, run the source publisher again to recover it."
        ),
    )
    installed = Path(sys.argv[0]).name == "l2solver-uninstall"
    parser.add_argument("--prefix", type=Path, default=installed_prefix(sys.argv[0]) if installed else Path("/usr/local"))
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--uninstall", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--payload", type=Path)
    action.add_argument("--retire-inactive", action="store_true", help="remove intact inactive generations after all clients have stopped")
    action.add_argument("--quarantine-inactive", metavar="GENERATION", help="isolate one damaged inactive generation for administrator inspection")
    action.add_argument("--revoke-active", action="store_true", help="remove the current helper file capability without installing a generation")
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
    ensure_directory(args.prefix)
    fd = os.open(args.prefix, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.check:
            recover(args.prefix)
            previous = read_manifest(args.prefix)
            if previous is None:
                for relative in links(args.prefix, completion_dirs):
                    safe_parents((args.prefix / relative).parent)
                    if os.path.lexists(args.prefix / relative):
                        raise ValueError(f"foreign destination: {args.prefix / relative}")
            elif completion_dirs is not None and previous["links"] != links(args.prefix, completion_dirs):
                print("warning: retaining existing completion destinations from the protected manifest", file=sys.stderr)
        elif args.retire_inactive:
            retire_inactive(args.prefix)
        elif args.quarantine_inactive:
            quarantine_inactive(args.prefix, args.quarantine_inactive)
        elif args.revoke_active:
            revoke_active(args.prefix)
        elif args.payload:
            install(args.payload, args.prefix, args.enable_active, completion_dirs)
        elif args.uninstall or installed:
            uninstall(args.prefix)
        else:
            parser.error("--payload is required for installation")
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation refused: {error}")
