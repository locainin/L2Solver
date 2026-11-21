#!/usr/bin/env python3
"""Build a payload for separate administrator review and publication."""
import argparse
import hashlib
import json
import os
import shlex
import shutil
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


def payload_manifest(payload, artifacts):
    return {"schema": 1, "files": {
        name: artifacts[name] if name in artifacts else {
            "sha256": system_install.digest(payload / name), "size": (payload / name).stat().st_size,
        }
        for name in system_install.PAYLOAD_FILES
    }}


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "An administrator must independently verify every file and digest against trusted references or a trusted build. "
            "Publish with a reviewed, root-protected system_install.py and pass the separately protected approval as --expected-manifest."
        ),
    )
    parser.add_argument("--output", type=Path, required=True, help="new directory for payload and proposed manifest")
    parser.add_argument("--live", action="store_true", help="also build optional libpcap receive support (requires libpcap development files)")
    parser.add_argument("--prefix", type=Path, default=Path("/usr/local"), help="intended prefix for completion suggestions; default /usr/local")
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
    args.output = Path(os.path.abspath(args.output))
    if os.path.lexists(args.output):
        parser.error("--output must not already exist")
    if not args.output.parent.is_dir():
        parser.error("the --output parent directory must already exist")
    for name in ("cargo", "rustc", "cc", "git", "ldd"):
        if not shutil.which(name):
            parser.error(f"missing dependency: {name}; install it and retry")
    # Record provenance before starting the build
    try:
        before = source_state()
    except subprocess.CalledProcessError:
        parser.error("source installation requires a Git checkout with a committed HEAD; clone the repository and run this script from that checkout")
    if args.live:
        if not shutil.which("pkg-config"):
            parser.error("missing dependency: pkg-config; install it and retry")
        if subprocess.run(["pkg-config", "--exists", "libpcap"], check=False).returncode:
            parser.error("libpcap was not found; install libpcap development files and retry")
    # Discover shell paths without running shell configuration as root
    selected = completion_paths.discover(args.prefix)
    completion_args = [part for shell, directory in selected.items()
                       for part in ("--completion-dir", f"{shell}={directory}")]
    with tempfile.TemporaryDirectory(prefix="l2solver-build-") as directory:
        workspace = Path(directory)
        artifacts = build_payload(args, before, workspace)
        payload = workspace / "payload"
        proposed = payload_manifest(payload, artifacts)
        (workspace / "manifest.json").write_text(json.dumps(proposed, indent=2, sort_keys=True) + "\n")
        # Exclusive creation avoids replacing an existing output directory
        args.output.mkdir(mode=0o700)
        shutil.move(payload, args.output / "payload")
        shutil.move(workspace / "manifest.json", args.output / "manifest.json")
    print(f"Prepared payload: {args.output / 'payload'}")
    print(f"Proposed manifest: {args.output / 'manifest.json'}")
    print("An administrator must independently verify every file and digest against trusted references or a trusted build before approving the proposed manifest")
    print(f"Suggested completion options: {shlex.join(completion_args)}")


def build_payload(args, before, workspace):
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
    identities = {}
    for name, (source, expected) in artifacts.items():
        binary = payload / name
        shutil.copyfile(source, binary)
        if system_install.digest(binary) != expected:
            raise ValueError(f"Cargo artifact changed while staging: {name}")
        # Keep Cargo's recorded digest rather than trusting a later payload rehash
        identities[name] = {"sha256": expected, "size": binary.stat().st_size}
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
        "profile": "release", "live": args.live,
        "version": output(str(binary), "--version"), "command": command,
    }
    (payload / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    # The administrator decides whether to make any copied binary executable
    for name in BINARIES:
        (payload / name).chmod(0o644)
    return identities


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"installation failed: {error}")
