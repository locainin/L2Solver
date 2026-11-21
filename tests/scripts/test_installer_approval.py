"""Check the administrator approval boundary without installing system files."""
import json
import os
from types import SimpleNamespace

import pytest

pytest_plugins = ["test_system_install"]


def proposed(installer, payload):
    return {"schema": 1, "files": {
        name: {"sha256": installer.digest(payload / name), "size": (payload / name).stat().st_size}
        for name in installer.PAYLOAD_FILES
    }}


@pytest.mark.parametrize("damage", ["missing", "extra", "hash", "schema", "boolean", "size", "size_boolean", "fields"])
def test_approved_manifest_rejects_incomplete_or_invalid_files(installer, payload, damage):
    manifest = proposed(installer, payload)
    if damage == "missing":
        manifest["files"].pop("fish")
    elif damage == "extra":
        manifest["files"]["extra"] = {"sha256": "a" * 64, "size": 1}
    elif damage == "hash":
        manifest["files"]["fish"]["sha256"] = "not-a-sha256"
    elif damage == "boolean":
        manifest["schema"] = True
    elif damage == "size":
        manifest["files"]["fish"]["size"] = -1
    elif damage == "size_boolean":
        manifest["files"]["fish"]["size"] = True
    elif damage == "fields":
        manifest["files"]["fish"]["other"] = 1
    else:
        manifest["schema"] = 2
    with pytest.raises(ValueError, match="approved manifest"):
        installer.validate_expected_manifest(manifest)


def test_approved_manifest_accepts_complete_digests(installer, payload):
    manifest = proposed(installer, payload)
    assert installer.validate_expected_manifest(manifest) == manifest["files"]


@pytest.mark.parametrize("mode,owner,links", [
    (0o100644, 1000, 1), (0o100664, 0, 1), (0o100646, 0, 1), (0o100644, 0, 2),
])
def test_trusted_file_rejects_unsafe_owner_mode_or_links(installer, mode, owner, links):
    info = SimpleNamespace(st_mode=mode, st_uid=owner, st_nlink=links)
    with pytest.raises(ValueError, match="untrusted"):
        installer.validate_trusted_metadata(info, directory=False)


def test_manifest_in_user_writable_tree_is_rejected(installer, payload, tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(proposed(installer, payload)))
    with pytest.raises(ValueError, match="untrusted"):
        installer.read_expected_manifest(manifest)


def test_manifest_duplicate_keys_are_rejected(installer, tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema": 1, "schema": 1, "files": {}}')
    monkeypatch.setattr(installer, "trusted_file", lambda path: os.open(path, os.O_RDONLY))
    with pytest.raises(ValueError, match="duplicate"):
        installer.read_expected_manifest(manifest)


def test_trusted_manifest_is_parsed(installer, payload, tmp_path, monkeypatch):
    expected = proposed(installer, payload)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(expected))
    monkeypatch.setattr(installer, "trusted_file", lambda path: os.open(path, os.O_RDONLY))
    assert installer.read_expected_manifest(manifest) == expected["files"]


def test_missing_approval_stops_before_destination_access(installer, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "argv", [
        "system_install.py", "--payload", str(tmp_path / "payload"), "--prefix", str(prefix),
    ])
    monkeypatch.setattr(installer, "safe_parents", lambda _: pytest.fail("destination accessed"))
    with pytest.raises(SystemExit):
        installer.main()
    assert not prefix.exists()


def test_untrusted_publisher_stops_before_approval(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    publisher = tmp_path / "system_install.py"
    publisher.touch()
    monkeypatch.setattr(installer, "__file__", str(publisher))
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "argv", [
        str(publisher), "--payload", str(payload), "--prefix", str(prefix),
        "--expected-manifest", "/trusted/approved.json",
    ])
    monkeypatch.setattr(installer, "read_expected_manifest", lambda _: pytest.fail("approval accessed"))
    with pytest.raises(ValueError, match="untrusted"):
        installer.main()
    assert not prefix.exists()


def test_digest_mismatch_stops_before_destination_or_capabilities(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    manifest = proposed(installer, payload)
    manifest["files"]["l2solver-active-helper"]["sha256"] = "0" * 64
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "argv", [
        "system_install.py", "--payload", str(payload), "--prefix", str(prefix),
        "--expected-manifest", "/trusted/approved.json", "--enable-active",
    ])
    monkeypatch.setattr(installer, "check_trusted_publisher", lambda: None)
    monkeypatch.setattr(installer, "read_expected_manifest", lambda _: manifest["files"])
    monkeypatch.setattr(installer, "ensure_directory", lambda _: pytest.fail("destination touched"))
    monkeypatch.setattr(installer, "enable_capability", lambda _: pytest.fail("capability granted"))
    with pytest.raises(ValueError, match="digest mismatch"):
        installer.main()
    assert not os.path.lexists(prefix)


def test_valid_approval_reaches_publication_with_private_copy(installer, payload, tmp_path, monkeypatch):
    prefix = tmp_path / "prefix"
    manifest = proposed(installer, payload)
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer.sys, "argv", [
        "system_install.py", "--payload", str(payload), "--prefix", str(prefix),
        "--expected-manifest", "/trusted/approved.json", "--enable-active",
    ])
    monkeypatch.setattr(installer, "check_trusted_publisher", lambda: None)
    monkeypatch.setattr(installer, "read_expected_manifest", lambda _: manifest["files"])
    monkeypatch.setattr(installer, "safe_parents", lambda _: None)
    published = []

    def publish(staged, actual_prefix, active, _completion_dirs):
        assert staged != payload
        assert actual_prefix == prefix and active
        assert {name: installer.digest(staged / name) for name in installer.PAYLOAD_FILES} == {
            name: value["sha256"] for name, value in manifest["files"].items()
        }
        published.append(True)

    monkeypatch.setattr(installer, "install", publish)
    installer.main()
    assert published == [True]


def test_verified_copy_matches_approved_manifest(installer, payload):
    manifest = proposed(installer, payload)
    with installer.verified_payload(payload, manifest["files"]) as staged:
        assert staged != payload
        assert {name: {"sha256": installer.digest(staged / name), "size": (staged / name).stat().st_size}
                for name in installer.PAYLOAD_FILES} == manifest["files"]
        assert all((staged / name).stat().st_mode & 0o777 == 0o600 for name in installer.PAYLOAD_FILES)


def test_unapproved_size_is_rejected(installer, payload):
    manifest = proposed(installer, payload)
    manifest["files"]["l2solver"]["size"] += 1
    with pytest.raises(ValueError, match="size mismatch"), installer.verified_payload(payload, manifest["files"]):
        pytest.fail("unapproved payload accepted")


def test_unexpected_payload_file_is_rejected(installer, payload):
    manifest = proposed(installer, payload)
    (payload / "extra").write_text("extra")
    with pytest.raises(ValueError, match="unexpected payload"), installer.verified_payload(payload, manifest["files"]):
        pytest.fail("unexpected file accepted")
