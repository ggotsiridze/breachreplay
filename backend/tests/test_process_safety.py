import subprocess
import sys
from pathlib import Path

import pytest

from app.analyzers import process as process_mod
from app.analyzers.process import AnalyzerError, run_command
from app.analyzers.suricata import build_suricata_command
from app.analyzers.zeek import build_zeek_command
from app.storage.workspace import CAPTURE_NAME, Workspace, new_job_id


def test_commands_are_argument_lists_without_user_input():
    zeek = build_zeek_command(Path("/w/abc/capture.pcap"))
    suri = build_suricata_command(Path("/w/abc/capture.pcap"), Path("/w/abc/suricata"))
    assert isinstance(zeek, list) and zeek[0] == "zeek" and "-r" in zeek
    assert isinstance(suri, list) and suri[0] == "suricata" and "-r" in suri
    assert "-D" in zeek  # deterministic UIDs
    assert all(isinstance(a, str) for a in zeek + suri)


def test_subprocess_uses_shell_false(monkeypatch, tmp_path):
    seen = {}
    real = subprocess.Popen

    def spy(*args, **kwargs):
        seen.update(kwargs)
        seen["argv"] = args[0]
        return real(*args, **kwargs)

    monkeypatch.setattr(process_mod.subprocess, "Popen", spy)
    result = run_command("python", [sys.executable, "-c", "print('ok')"], cwd=tmp_path, timeout_seconds=10)
    assert result.returncode == 0
    assert seen["shell"] is False
    assert isinstance(seen["argv"], list)
    assert set(seen["env"]) <= {"PATH", "LANG", "HOME"}  # no inherited secrets


def test_shell_string_rejected(tmp_path):
    with pytest.raises(AnalyzerError):
        run_command("zeek", "zeek -r /etc/passwd; rm -rf /", cwd=tmp_path, timeout_seconds=1)  # type: ignore[arg-type]


def test_shell_metacharacters_are_not_interpreted(tmp_path):
    marker = tmp_path / "pwned"
    result = run_command("python", [sys.executable, "-c", "import sys; print(sys.argv[1])", f"; touch {marker}"], cwd=tmp_path, timeout_seconds=10)
    assert result.returncode == 0
    assert not marker.exists()


def test_analyzer_timeout_kills_process(tmp_path):
    with pytest.raises(AnalyzerError) as exc:
        run_command("python", [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout_seconds=0.5)
    assert exc.value.timed_out


def test_missing_binary_is_reported(tmp_path):
    with pytest.raises(AnalyzerError) as exc:
        run_command("zeek", ["definitely-not-a-real-binary-xyz"], cwd=tmp_path, timeout_seconds=1)
    assert "not installed or not executable" in exc.value.message


def test_generated_internal_filenames(tmp_path):
    job = new_job_id()
    ws = Workspace(tmp_path, job).create()
    assert ws.capture.name == CAPTURE_NAME
    assert ws.path.parent == tmp_path
    assert len(job) == 32


@pytest.mark.parametrize("bad", ["../etc", "x" * 32, "ABCDEF" + "0" * 26, ""])
def test_workspace_rejects_untrusted_ids(tmp_path, bad):
    with pytest.raises(ValueError):
        Workspace(tmp_path, bad)


def test_workspace_cleanup(tmp_path):
    ws = Workspace(tmp_path, new_job_id()).create()
    ws.capture.write_bytes(b"data")
    (ws.path / "zeek").mkdir()
    (ws.path / "zeek" / "conn.log").write_text("x")
    ws.cleanup()
    assert not ws.path.exists()
