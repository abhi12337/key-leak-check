import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FAKE, SECRET_KEYS
from key_leak_check.cli import main
from key_leak_check.findings import FRAMEWORKS, RULES, SEVERITIES, Finding, mask_secret, redact_line

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def run(capsys, *argv):
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_scan_vulnerable_text_report(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "next_vulnerable"), "--no-color")
    assert code == 1
    assert "CRITICAL KLC002" in out and "app/chat/page.tsx:5" in out
    assert "why:" in out and "fix:" in out and "app/api/ai/route.ts" in out
    assert "Frameworks: next" in out and "Exit code: 1" in out


def test_scan_clean_exits_0(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "next_clean"), str(FIX / "vite_clean"), "--no-color")
    assert code == 0
    assert "No findings" in out and "1 env file(s)" in out


def test_json_report_shape(capsys):
    code, out, _ = run(capsys, "scan", str(FIX / "vite_vulnerable"), "--json")
    doc = json.loads(out)
    assert code == 1 and doc["exit_code"] == 1 and doc["tool"] == "key-leak-check"
    assert doc["frameworks"] == ["vite"] and doc["source_files"] == 3
    assert set(doc["summary"]) == set(SEVERITIES)
    first = doc["findings"][0]
    assert first["severity"] == "critical"
    assert {"rule_id", "severity", "message", "file", "line", "evidence", "title", "why", "fix"} <= set(first)


def test_fail_on_min_severity_and_disable(capsys):
    target = str(FIX / "next_vulnerable")
    assert run(capsys, "scan", target, "--fail-on", "never")[0] == 0
    code, out, _ = run(capsys, "scan", target, "--json", "--min-severity", "critical")
    assert {f["severity"] for f in json.loads(out)["findings"]} == {"critical"} and code == 1
    code, out, _ = run(capsys, "scan", target, "--json", "--disable", "KLC002", "--disable", "klc003")
    assert json.loads(out)["findings"] == [] and code == 0
    code, _, _ = run(capsys, "scan", target, "--json", "--disable", "KLC002")
    assert code == 1                                         # KLC003 is high
    assert run(capsys, "scan", target, "--disable", "KLC002", "--fail-on", "critical")[0] == 0


def test_fail_on_medium_counts_medium(capsys, make_repo):
    root = make_repo({"dist/a.js": "x", "dist/a.js.map": "{}"})
    assert run(capsys, "scan", str(root))[0] == 0
    assert run(capsys, "scan", str(root), "--fail-on", "medium")[0] == 1


def test_unknown_rule_and_missing_path(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "nope"))
    assert code == 2 and "does not exist" in err
    code, _, err = run(capsys, "scan", str(tmp_path), "--disable", "KLC999")
    assert code == 2 and "unknown rule" in err
    with pytest.raises(SystemExit) as e:
        main(["scan", "--fail-on", "sometimes"])
    assert e.value.code == 2


def test_scan_single_files(capsys, make_repo, fake):
    root = make_repo({".env.production": f"VITE_OPENAI_API_KEY={fake['openai']}\n",
                      "src/x.ts": f'const k = "{fake["groq"]}";\n'})
    code, out, _ = run(capsys, "scan", str(root / ".env.production"), str(root / "src" / "x.ts"), "--json")
    doc = json.loads(out)
    assert code == 1
    assert sorted(f["rule_id"] for f in doc["findings"]) == ["KLC001", "KLC004", "KLC007"]
    assert all(f["file"].endswith((".env.production", "x.ts")) for f in doc["findings"])


def test_no_include_build_flag(capsys, make_repo, fake):
    root = make_repo({"dist/a.js": f'var k="{fake["openai"]}";'})
    assert run(capsys, "scan", str(root))[0] == 1
    code, out, _ = run(capsys, "scan", str(root), "--no-include-build", "--no-color")
    assert code == 0 and "Build output skipped" in out


def test_output_never_contains_secrets(capsys, make_repo, fake):
    """Every fake secret, everywhere the scanner looks: no full value and nothing beyond the
    first 4 characters may appear in text or JSON output."""
    env_lines = "".join(f"NEXT_PUBLIC_{k.upper()}_SECRET={fake[k]}\n" for k in SECRET_KEYS)
    env_lines += "".join(f"{k.upper()}_API_KEY={fake[k]}\n" for k in SECRET_KEYS)
    code_lines = "".join(f'export const {k} = "{fake[k]}";\n' for k in SECRET_KEYS)
    root = make_repo({
        "package.json": {"dependencies": {"next": "15.0.0"}},
        ".env.local": env_lines,
        ".env.example": env_lines,
        "app/page.tsx": '"use client";\nimport { GoogleGenAI } from "@google/genai";\n' + code_lines,
        "app/api/x/route.ts": code_lines,
        "Dockerfile": "".join(f"ENV VITE_{k.upper()}_SECRET={fake[k]}\n" for k in SECRET_KEYS),
        "dist/assets/a.js": "var g='generativelanguage';" + "".join(f'var {k}="{fake[k]}";' for k in SECRET_KEYS),
    })
    for fmt in ([], ["--json"], ["--brief"]):
        code, out, _ = run(capsys, "scan", str(root), "--no-color", *fmt)
        assert code == 1
        for name in SECRET_KEYS:
            secret = fake[name]
            assert secret not in out, name
            assert secret[4:12] not in out, name      # never more than the first 4 characters
    assert FAKE["db_password"] not in out


def test_mask_secret_shows_at_most_four_chars():
    assert mask_secret("abcdefghijklmnopqrstuvwxyz") == "abcd**** (26 chars)"
    assert mask_secret("abcdefgh") == "ab**** (8 chars)"
    assert mask_secret("abc") == "**** (3 chars)"


def test_redact_line_masks_unknown_formats_and_url_passwords():
    pw = FAKE["db_password"]
    assert pw not in redact_line(f"DATABASE_URL=postgres://u:{pw}@db.example.com/x")
    rnd = FAKE["generic"]
    assert rnd not in redact_line(f'const razorpaySecret = "{rnd}";')
    assert redact_line("const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;") == \
        "const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;"


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    for rid in RULES:
        assert rid in out


def test_every_rule_has_title_why_fix():
    for r in RULES.values():
        assert r.title and len(r.why) > 40 and len(r.fix) > 40


@pytest.mark.parametrize("fw", [*FRAMEWORKS, None])
@pytest.mark.parametrize("rid", ["KLC001", "KLC002", "KLC003", "KLC004", "KLC005"])
def test_fix_has_rotation_proxy_and_naming_for_every_framework(rid, fw):
    f = Finding(rid, "critical", "", extra={"framework": fw, "provider": "openai", "var": "VITE_OPENAI_API_KEY"})
    text = f.fix
    assert "otate" in text and "OPENAI_API_KEY" in text and "<" not in text.replace("<voice_id>", "")
    assert "api.openai.com" in text                         # the server-side proxy snippet
    assert "VITE_OPENAI_API_KEY" not in text or "->" in text or rid in ("KLC003",)


def test_module_entry_point():
    env = {"PYTHONPATH": str(ROOT / "src")}
    if sys.platform == "win32":
        env.update({"SYSTEMROOT": "C:\\Windows", "PATH": ""})
    res = subprocess.run([sys.executable, "-m", "key_leak_check", "scan", str(FIX / "vite_clean"), "--brief"],
                         capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    assert "No findings" in res.stdout


def test_no_network_imports():
    """The scanner must never be able to contact anything."""
    for p in (ROOT / "src" / "key_leak_check").glob("*.py"):
        text = p.read_text(encoding="utf-8")
        for mod in ("urllib.request", "http.client", "socket", "requests", "httpx", "ssl"):
            assert f"import {mod}" not in text and f"from {mod} import" not in text, (p.name, mod)


def test_repository_contains_no_secret_shaped_strings():
    """Fixtures and examples must stay free of anything a secret scanner would flag."""
    from key_leak_check.patterns import find_tokens
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts or ".pytest_cache" in p.parts:
            continue
        if p.suffix not in (".py", ".ts", ".tsx", ".js", ".json", ".md", ".yml", ".toml", ".txt", ".example", ""):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        assert find_tokens(text) == [], p


@pytest.mark.parametrize("name", ["next_vulnerable", "vite_vulnerable"])
def test_every_finding_has_location_evidence_and_fix(capsys, name):
    _, out, _ = run(capsys, "scan", str(FIX / name), "--json")
    for f in json.loads(out)["findings"]:
        assert f["file"] and f["line"] and f["evidence"] and f["fix"] and f["why"]
