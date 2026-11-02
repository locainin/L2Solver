"""Find shell completion paths without running shell configuration as root."""

import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import system_install


def relative_candidate(prefix, value):
    path = Path(value)
    if not path.is_absolute():
        return None
    try:
        relative = str(path.relative_to(prefix))
        return system_install.completion_directory(relative)
    except ValueError:
        return None


def select_directory(prefix, shell, reported):
    for value in reported:
        relative = relative_candidate(prefix, value)
        if relative is not None:
            return relative, True
    return system_install.COMPLETION_CANDIDATES[shell][0], False


def probe(command, environment):
    executable = shutil.which(command[0])
    if executable is None:
        return []
    try:
        with subprocess.Popen(
            [executable, *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            start_new_session=True,
        ) as process:
            completed = False
            try:
                # Stop a noisy or stalled probe before it can exhaust resources
                deadline = time.monotonic() + 5
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            return []
                        chunk = os.read(process.stdout.fileno(), min(8192, 65_537 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > 65_536:
                            return []
                if process.wait(timeout=max(0, deadline - time.monotonic())):
                    completed = True
                    return []
                completed = True
                return data.decode("utf-8").splitlines()
            finally:
                if not completed:
                    # Stop the probe and children that share its process group
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
    except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
        return []


def discover(prefix):
    prefix = Path(os.path.abspath(prefix))
    environment = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="l2solver-shell-probe-") as directory:
        # Isolate per-user startup files; global shell configuration runs unprivileged
        environment.update({
            "HOME": directory,
            "ZDOTDIR": directory,
            "XDG_CONFIG_HOME": f"{directory}/config",
            "XDG_DATA_HOME": f"{directory}/data",
            "XDG_CACHE_HOME": f"{directory}/cache",
            "XDG_STATE_HOME": f"{directory}/state",
        })
        bash = probe(["pkg-config", "--variable=completionsdir", "bash-completion"], environment)
        data_dirs = environment.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
        bash.extend(f"{path}/bash-completion/completions" for path in data_dirs.split(":") if path)
        reported = {
            "bash": bash,
            "zsh": probe(["zsh", "-f", "-c", "print -rl -- $fpath"], environment),
            "fish": probe(["fish", "-c", 'printf "%s\\n" $fish_complete_path'], environment),
        }
    selected = {}
    for shell, paths in reported.items():
        selected[shell], found = select_directory(prefix, shell, paths)
        if not found:
            print(
                f"warning: {shell} reported no safe completion path under {prefix}; "
                f"using {selected[shell]} (shell configuration may need updating)",
                file=sys.stderr,
            )
    return selected
