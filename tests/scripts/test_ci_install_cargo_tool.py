"""Exercise the pinned CI tool installer and its Nextest configuration."""

import io
import os
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/ci/install-cargo-tool.sh"
NEXTEST_CONFIG = ROOT / ".config/nextest.toml"
NEXTEST_VERSION = "0.9.150"


def nextest_fixture_environment(tmp_path, members, checksum_status=0):
    # Keep version fixtures offline while using the real tar and install commands
    archive = tmp_path / "nextest.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, data in members.items():
            content = data.encode()
            member = tarfile.TarInfo(name)
            member.mode = 0o755
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))

    commands = tmp_path / "commands"
    commands.mkdir()
    curl = commands / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$CURL_ARGUMENTS\"\n"
        "while [ \"$1\" != --output ]; do shift; done\n"
        "cp \"$FIXTURE_ARCHIVE\" \"$2\"\n"
    )
    curl.chmod(0o755)
    checksum = commands / "sha256sum"
    # Fixture archives differ from the published archive, so bypass its pinned hash
    checksum.write_text(
        "#!/bin/sh\n"
        "cat > /dev/null\n"
        f"exit {checksum_status}\n"
    )
    checksum.chmod(0o755)
    return {
        **os.environ,
        "HOME": str(tmp_path),
        "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}",
        "FIXTURE_ARCHIVE": str(archive),
        "CURL_ARGUMENTS": str(tmp_path / "curl-arguments"),
    }


def run_nextest_installer(tmp_path, env):
    return subprocess.run(
        ["bash", str(INSTALLER), "nextest"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def fixture_binary(version, status=0):
    return (
        "#!/bin/sh\n"
        "[ \"$1\" = --version ] || exit 90\n"
        f"printf 'cargo-nextest {version} (fixture)\\n'\n"
        f"exit {status}\n"
    )


def test_nextest_installs_pinned_version_and_only_the_expected_member(tmp_path):
    # An unrelated archive member must never escape the scratch directory
    escaped_name = f"{tmp_path.name}-escaped"
    env = nextest_fixture_environment(
        tmp_path,
        {
            "cargo-nextest": fixture_binary(NEXTEST_VERSION),
            f"../{escaped_name}": "unexpected archive member",
        },
    )
    result = run_nextest_installer(tmp_path, env)
    assert result.returncode == 0, result.stderr
    binary = tmp_path / ".cargo/bin/cargo-nextest"
    version = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, check=True, timeout=20
    )
    assert version.stdout == f"cargo-nextest {NEXTEST_VERSION} (fixture)\n"
    assert not (tmp_path.parent / escaped_name).exists()
    arguments = (tmp_path / "curl-arguments").read_text().splitlines()
    assert arguments[arguments.index("--proto") + 1] == "=https"
    assert arguments[arguments.index("--proto-redir") + 1] == "=https"
    assert arguments[-1] == (
        "https://github.com/nextest-rs/nextest/releases/download/"
        f"cargo-nextest-{NEXTEST_VERSION}/"
        f"cargo-nextest-{NEXTEST_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
    )


@pytest.mark.parametrize(
    ("version", "status", "diagnostic"),
    # A failed command remains a failure even if it prints the expected version
    [
        ("0.9.149", 0, f"unexpected cargo-nextest version; expected {NEXTEST_VERSION}"),
        (NEXTEST_VERSION, 23, "failed to check cargo-nextest version"),
    ],
    ids=["wrong-version", "version-command-failed"],
)
def test_nextest_rejects_bad_version_without_replacing_installed_tool(
    tmp_path, version, status, diagnostic
):
    env = nextest_fixture_environment(
        tmp_path, {"cargo-nextest": fixture_binary(version, status)}
    )
    installed = tmp_path / ".cargo/bin/cargo-nextest"
    installed.parent.mkdir(parents=True)
    installed.write_text("previous tool")
    result = run_nextest_installer(tmp_path, env)
    assert result.returncode != 0
    assert diagnostic in result.stderr
    assert installed.read_text() == "previous tool"


def test_nextest_rejects_an_archive_without_the_expected_member(tmp_path):
    env = nextest_fixture_environment(tmp_path, {"other": fixture_binary(NEXTEST_VERSION)})
    result = run_nextest_installer(tmp_path, env)
    assert result.returncode != 0
    assert not (tmp_path / ".cargo/bin/cargo-nextest").exists()


def test_failed_download_does_not_replace_the_installed_tool(tmp_path):
    env = nextest_fixture_environment(tmp_path, {"cargo-nextest": fixture_binary(NEXTEST_VERSION)})
    curl = tmp_path / "commands/curl"
    curl.write_text("#!/bin/sh\nexit 28\n")
    installed = tmp_path / ".cargo/bin/cargo-nextest"
    installed.parent.mkdir(parents=True)
    installed.write_text("previous tool")
    result = run_nextest_installer(tmp_path, env)
    assert result.returncode != 0
    assert installed.read_text() == "previous tool"


def test_failed_checksum_stops_before_extracting_or_replacing_the_tool(tmp_path):
    env = nextest_fixture_environment(
        tmp_path, {"cargo-nextest": fixture_binary(NEXTEST_VERSION)}, checksum_status=1
    )
    tar = tmp_path / "commands/tar"
    # A marker makes any extraction attempt visible when checksum validation fails
    tar.write_text("#!/bin/sh\ntouch \"$HOME/tar-ran\"\nexit 1\n")
    tar.chmod(0o755)
    installed = tmp_path / ".cargo/bin/cargo-nextest"
    installed.parent.mkdir(parents=True)
    installed.write_text("previous tool")
    result = run_nextest_installer(tmp_path, env)
    assert result.returncode != 0
    assert not (tmp_path / "tar-ran").exists()
    assert installed.read_text() == "previous tool"


def test_nextest_configuration_requires_the_patched_version():
    with NEXTEST_CONFIG.open("rb") as config:
        assert tomllib.load(config)["nextest-version"] == NEXTEST_VERSION


def test_unknown_tool_is_rejected_before_downloading(tmp_path):
    result = subprocess.run(
        ["bash", str(INSTALLER), "unknown"],
        env={**os.environ, "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "unknown" in result.stderr
    assert not (tmp_path / ".cargo/bin/unknown").exists()


def test_download_with_wrong_checksum_never_installs_a_binary(tmp_path):
    # Keep the real checksum command for this rejected download
    commands = tmp_path / "commands"
    commands.mkdir()
    curl = commands / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        "while [ \"$1\" != --output ]; do shift; done\n"
        "printf invalid > \"$2\"\n"
    )
    curl.chmod(0o755)
    result = subprocess.run(
        ["bash", str(INSTALLER), "nextest"],
        env={**os.environ, "HOME": str(tmp_path), "PATH": f"{commands}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "FAILED" in result.stdout or "FAILED" in result.stderr
    assert not (tmp_path / ".cargo/bin/cargo-nextest").exists()
