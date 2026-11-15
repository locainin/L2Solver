#!/usr/bin/env python3
"""Build the locked source as an ordinary user, then publish the reviewed payload."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import completion_paths
import system_install

BINARIES = system_install.BINARIES


def output(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()


def source_state():
    # Include untracked files since a Rust module can compile before it is added to Git
    return {
        "source": output("git", "rev-parse", "HEAD"),
        "source_tree": output("git", "rev-parse", "HEAD^{tree}"),
        "source_dirty": bool(output("git", "status", "--porcelain", "--untracked-files=all")),
    }


def stage_publisher(directory):
    source = ROOT / "scripts/system_install.py"
    # The launcher itself must come from a trusted checkout
    system_install.safe_parents(source.parent)
    temporary_root = Path(tempfile.gettempdir())
    system_install.safe_parents(temporary_root)
    if temporary_root.stat().st_uid not in (0, os.geteuid()):
        raise ValueError(f"untrusted temporary directory: {temporary_root}")
    parent = system_install.open_directory(source.parent)
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.geteuid())
                    or before.st_nlink != 1 or before.st_mode & 0o022):
                raise ValueError(f"untrusted publisher: {source}")
            original = hashlib.file_digest(stream, "sha256").hexdigest()
            stream.seek(0)
            publisher = directory / "system_install.py"
            with publisher.open("xb") as target:
                shutil.copyfileobj(stream, target)
            stream.seek(0)
            after_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
            named = os.stat(source.name, dir_fd=parent, follow_symlinks=False)
            if (original != after_hash or original != system_install.digest(publisher)
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise ValueError("publisher changed while staging")
            return publisher
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enable-active", action="store_true", help="explicitly grant CAP_NET_RAW only to the matching helper")
    parser.add_argument("--live", action="store_true", help="also build optional libpcap receive support (requires libpcap development files)")
    parser.add_argument("--prefix", type=Path, default=Path("/usr/local"), help="protected local prefix; default /usr/local")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("run this Linux source installer as an ordinary user; Cargo must never run as root")
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required")
    if not args.prefix.is_absolute():
        parser.error("--prefix must be an absolute local installation directory")
    args.prefix = Path(os.path.abspath(args.prefix))
    if args.prefix == Path("/"):
        parser.error("--prefix must be an absolute local installation directory")
    for name in ("cargo", "rustc", "cc", "git", "sudo", "ldd"):
        if not shutil.which(name):
            parser.error(f"missing dependency: {name}; install it and retry")
    system_python = subprocess.run(
        ["/usr/bin/python3", "-I", "-c", "import sys; sys.exit(sys.version_info < (3, 11))"],
        check=False,
    )
    if system_python.returncode:
        parser.error("/usr/bin/python3 must be Python 3.11 or newer")
    # Confirm provenance before inspecting a protected prefix or starting a build
    try:
        before = source_state()
    except subprocess.CalledProcessError:
        parser.error("source installation requires a Git checkout with a committed HEAD; clone the repository and run this script from that checkout")
    if args.enable_active:
        for name in ("setcap", "getcap"):
            if not shutil.which(name):
                parser.error(f"missing dependency: {name}; install libcap tools and retry")
    for name in (*BINARIES, "l2solver-uninstall"):
        found = shutil.which(name)
        expected = args.prefix / "bin" / name
        if found and Path(found).absolute() != expected:
            parser.error(f"PATH collision: {found}; resolve it before installing {expected}")
    if args.live:
        if not shutil.which("pkg-config"):
            parser.error("missing dependency: pkg-config; install it and retry")
        if subprocess.run(["pkg-config", "--exists", "libpcap"], check=False).returncode:
            parser.error("libpcap was not found; install libpcap development files and retry")
    # Discover shell paths before sudo, with per-user startup files isolated
    selected = completion_paths.discover(args.prefix)
    completion_args = [part for shell, directory in selected.items()
                       for part in ("--completion-dir", f"{shell}={directory}")]
    # Check local directory trust before validating protected records through sudo
    system_install.safe_parents(args.prefix)
    with tempfile.TemporaryDirectory(prefix="l2solver-install-") as directory:
        workspace = Path(directory)
        publisher = stage_publisher(workspace)
        subprocess.run(["sudo", "/usr/bin/python3", "-I", str(publisher), "--check", "--prefix", str(args.prefix), *completion_args], check=True)
        build_and_publish(args, completion_args, before, publisher, workspace)
    print(f"Installed {args.prefix / 'bin/l2solver'}; receipt: {args.prefix / 'share/l2solver/current/receipt.json'}")
    if not args.enable_active:
        print("Active packet access is disabled; an administrator must explicitly enable the matching helper's CAP_NET_RAW capability")


def build_and_publish(args, completion_args, before, publisher, workspace):
    command = ["cargo", "build", "--release", "--locked", "-p", "l2-cli", "-p", "l2-active-cli", "-p", "l2-active-linux", "--bins", "--message-format=json-render-diagnostics"]
    if args.live:
        command.extend(["--features", "l2-cli/live"])
    target = workspace / "target"
    target.mkdir(mode=0o700)
    artifacts = {}
    # A private target keeps other builds from replacing these executables
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True,
                          env={**os.environ, "CARGO_TARGET_DIR": str(target),
                               "CARGO_BUILD_BUILD_DIR": str(target)}) as process:
        for line in process.stdout:
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact" and message.get("executable"):
                name = message["target"]["name"]
                if name in BINARIES:
                    path = Path(message["executable"])
                    if not path.resolve().is_relative_to(target.resolve()):
                        raise ValueError(f"Cargo artifact is outside the private target: {name}")
                    # Match the staged copy to Cargo's reported executable
                    artifacts[name] = (path, system_install.digest(path))
        if process.wait() != 0:
            raise ValueError("locked release build failed; nothing installed")
    if set(artifacts) != set(BINARIES):
        raise ValueError("Cargo did not produce the complete executable set")
    after = source_state()
    if (before["source"], before["source_tree"]) != (after["source"], after["source_tree"]):
        raise ValueError("source commit changed during build; nothing installed")
    payload = workspace / "payload"
    payload.mkdir()
    for name, (source, expected) in artifacts.items():
        binary = payload / name
        shutil.copyfile(source, binary)
        if system_install.digest(binary) != expected:
            raise ValueError(f"Cargo artifact changed while staging: {name}")
        binary.chmod(0o755)
        dependencies = subprocess.run(
            ["ldd", str(binary)], check=True, capture_output=True, text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        # ldd may return success while reporting a missing shared library
        lines = (dependencies.stdout + dependencies.stderr).splitlines()
        missing = [line.strip() for line in lines if "=> not found" in line]
        if missing:
            raise ValueError(f"{name} has missing runtime dependencies: {', '.join(missing)}")
        sqlite = [line.strip() for line in lines if line.strip().startswith("libsqlite3.so")]
        if sqlite:
            raise ValueError(f"{name} unexpectedly depends on system SQLite: {', '.join(sqlite)}")
    binary = payload / "l2solver"
    for shell in ("bash", "zsh", "fish"):
        (payload / shell).write_text(output(str(binary), "completions", shell) + "\n")
    shutil.copyfile(ROOT / "NOTICE-JEMALLOC.txt", payload / "NOTICE-JEMALLOC.txt")
    receipt = {
        **after,
        "source_dirty": before["source_dirty"] or after["source_dirty"],
        "tracked_changes": output("git", "diff", "HEAD", "--stat"),
        "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
        "cargo": output("cargo", "--version"), "rustc": output("rustc", "--version"),
        "profile": "release", "live": args.live, "active_capability": args.enable_active,
        "version": output(str(binary), "--version"), "command": command,
    }
    (payload / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    publish = ["sudo", "/usr/bin/python3", "-I", str(publisher), "--payload", str(payload), "--prefix", str(args.prefix), *completion_args]
    if args.enable_active:
        publish.append("--enable-active")
    subprocess.run(publish, check=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation failed: {error}")
