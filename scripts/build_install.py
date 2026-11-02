#!/usr/bin/env python3
"""Build the locked source as an ordinary user, then publish the reviewed payload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import system_install
import completion_paths

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
    subprocess.run(["sudo", "/usr/bin/python3", "-I", str(ROOT / "scripts/system_install.py"), "--check", "--prefix", str(args.prefix), *completion_args], check=True)
    command = ["cargo", "build", "--release", "--locked", "-p", "l2-cli", "-p", "l2-active-cli", "-p", "l2-active-linux", "--bins", "--message-format=json-render-diagnostics"]
    if args.live:
        command.extend(["--features", "l2-cli/live"])
    before = source_state()
    artifacts = {}
    # Cargo supplies exact artifact paths, including configured target directories
    with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact" and message.get("executable"):
                name = message["target"]["name"]
                if name in BINARIES:
                    artifacts[name] = Path(message["executable"])
        if process.wait() != 0:
            raise ValueError("locked release build failed; nothing installed")
    if set(artifacts) != set(BINARIES):
        raise ValueError("Cargo did not produce the complete executable set")
    after = source_state()
    if (before["source"], before["source_tree"]) != (after["source"], after["source_tree"]):
        raise ValueError("source commit changed during build; nothing installed")
    with tempfile.TemporaryDirectory(prefix="l2solver-install-") as directory:
        payload = Path(directory)
        for name, binary in artifacts.items():
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
            shutil.copyfile(binary, payload / name)
        binary = artifacts["l2solver"]
        for shell in ("bash", "zsh", "fish"):
            (payload / shell).write_text(output(str(binary), "completions", shell) + "\n")
        for name in ("README.md", "NOTICE-JEMALLOC.txt"):
            shutil.copyfile(ROOT / name, payload / name)
        shutil.copyfile(ROOT / "docs/active/install.md", payload / "install.md")
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
        publish = ["sudo", "/usr/bin/python3", "-I", str(ROOT / "scripts/system_install.py"), "--payload", directory, "--prefix", str(args.prefix), *completion_args]
        if args.enable_active:
            publish.append("--enable-active")
        subprocess.run(publish, check=True)
    print(f"Installed {args.prefix / 'bin/l2solver'}; receipt: {args.prefix / 'share/l2solver/current/receipt.json'}")
    if not args.enable_active:
        print("Active packet access is disabled; an administrator must explicitly enable the matching helper's CAP_NET_RAW capability")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation failed: {error}")
