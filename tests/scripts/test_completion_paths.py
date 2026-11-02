"""Check that shell completion discovery respects the selected install prefix."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def discovery(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("completion_paths", ROOT / "scripts/completion_paths.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_selects_first_reported_completion_search_path_inside_prefix(discovery, tmp_path):
    prefix = tmp_path / "prefix"
    reported = [
        "/usr/share/fish/vendor_completions.d",
        str(prefix / "share/custom/fish"),
        str(prefix / "share/fish/vendor_completions.d"),
    ]
    assert discovery.select_directory(prefix, "fish", reported) == ("share/custom/fish", True)


def test_falls_back_when_only_external_or_unsafe_paths_are_reported(discovery, tmp_path):
    prefix = tmp_path / "prefix"
    reported = [
        "/usr/share/zsh/site-functions",
        str(prefix / "share/l2solver/inside"),
        str(prefix / "share/../escape"),
        "relative/path",
    ]
    assert discovery.select_directory(prefix, "zsh", reported) == ("share/zsh/site-functions", False)


def test_discovery_runs_unprivileged_probes_with_isolated_user_config(discovery, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    commands = tmp_path / "commands"
    commands.mkdir()
    marker = tmp_path / "observed-homes"
    shell = shutil.which("sh")
    assert shell is not None
    for name, directory in (
        ("zsh", "share/custom/zsh"),
        ("fish", "share/custom/fish"),
    ):
        command = commands / name
        command.write_text(
            f"#!{shell}\n"
            'printf "%s\\n" "$HOME" >> "$PROBE_MARKER"\n'
            f'printf "%s\\n" "$PROBE_PREFIX/{directory}"\n'
        )
        command.chmod(0o755)
    pkg_config = commands / "pkg-config"
    pkg_config.write_text(
        f"#!{shell}\n"
        'printf "%s\\n" "$PROBE_PREFIX/share/custom/bash"\n'
    )
    pkg_config.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.defpath)
    monkeypatch.setenv("PROBE_PREFIX", str(prefix))
    monkeypatch.setenv("PROBE_MARKER", str(marker))
    result = discovery.discover(prefix)
    assert result == {
        "bash": "share/custom/bash",
        "zsh": "share/custom/zsh",
        "fish": "share/custom/fish",
    }
    homes = marker.read_text().splitlines()
    assert len(homes) == 2
    assert all(home != os.environ.get("HOME") for home in homes)


def test_probe_stops_program_when_output_exceeds_its_limit(discovery, tmp_path):
    marker = tmp_path / "finished-output"
    program = tmp_path / "noisy-program"
    program.write_text(
        f"#!{shutil.which('python3')}\n"
        "import os\nfrom pathlib import Path\n"
        "for _ in range(64):\n    os.write(1, b'x' * 65536)\n"
        f"Path({str(marker)!r}).touch()\n"
    )
    program.chmod(0o755)
    assert discovery.probe([str(program)], dict(os.environ)) == []
    assert not marker.exists()


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_reported_prefix_path_loads_completion_in_real_shell(discovery, tmp_path, monkeypatch, shell):
    if not shutil.which(shell):
        pytest.skip(f"{shell} is unavailable for completion loading")
    prefix = tmp_path / "prefix"
    bash_path = prefix / "share/bash-completion/completions"
    zsh_path = prefix / "share/zsh/custom"
    fish_path = prefix / "share/fish/vendor_completions.d"
    for directory in (bash_path, zsh_path, fish_path):
        directory.mkdir(parents=True)
    binary = prefix / "bin/l2solver"
    binary.parent.mkdir()
    binary.write_text(f"#!{shutil.which('sh')}\n")
    binary.chmod(0o755)
    (bash_path / "l2solver").write_text("complete -W example_option l2solver\n")
    (zsh_path / "_l2solver").write_text('#compdef l2solver\n_arguments "1:choice:(example_option)"\n')
    (fish_path / "l2solver.fish").write_text("complete -c l2solver -f -a example_option\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("ZDOTDIR", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_DIRS", f"{prefix}/share:/usr/share")
    monkeypatch.setenv("PATH", f"{prefix}/bin{os.pathsep}{os.defpath}")
    if shutil.which("zsh"):
        defaults = subprocess.check_output(["zsh", "-f", "-c", "print -rl -- $fpath"], text=True).splitlines()
        monkeypatch.setenv("FPATH", os.pathsep.join([str(zsh_path), *defaults]))
    selected = discovery.discover(prefix)
    if shell == "bash":
        metadata = subprocess.run(["pkg-config", "--variable=datadir", "bash-completion"], text=True, capture_output=True, check=False)
        runtime = Path(metadata.stdout.strip()) / "bash-completion/bash_completion"
        if metadata.returncode or not runtime.is_file():
            pytest.skip("bash-completion runtime and pkg-config metadata are unavailable")
        assert selected[shell] == str(bash_path.relative_to(prefix))
        command = ["bash", "--noprofile", "--norc", "-c", 'source "$1"; if declare -F _comp_load >/dev/null; then _comp_load l2solver; else _completion_loader l2solver; fi; complete -p l2solver', "bash", str(runtime)]
    elif shell == "zsh":
        assert selected[shell] == str(zsh_path.relative_to(prefix))
        command = ["zsh", "-f", "-c", "autoload -Uz compinit; compinit -i -D; whence -w _l2solver"]
    else:
        assert selected[shell] == str(fish_path.relative_to(prefix))
        command = ["fish", "-c", 'complete -C "l2solver exa"']
    result = subprocess.run(command, text=True, capture_output=True, timeout=10, check=True)
    assert ("_l2solver: function" if shell == "zsh" else "example_option") in result.stdout
