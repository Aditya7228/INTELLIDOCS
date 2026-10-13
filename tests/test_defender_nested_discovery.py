from backend.security.malware_scanner import MalwareScannerAdapter


def test_discovers_windows_defender_cli_nested_under_x86(tmp_path, monkeypatch):
    platform = tmp_path / "ProgramData" / "Microsoft" / "Windows Defender" / "Platform"
    binary = platform / "4.18.26080.4-0" / "X86" / "MpCmdRun.exe"
    binary.parent.mkdir(parents=True)
    binary.write_text("test placeholder", encoding="utf-8")

    monkeypatch.delenv("MPCMD_RUN_PATH", raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "pfx86"))
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))
    monkeypatch.setattr("backend.security.malware_scanner.shutil.which", lambda _name: None)

    resolved, detail = MalwareScannerAdapter._resolve_windows_defender()

    assert resolved == str(binary.resolve())
    assert detail == ""
