from codevalidator.llm_review import cross_check
from codevalidator.models import Finding, Severity


def _f(provider, file, line, summary, confidence="medium"):
    return Finding(scanner="llm", severity=Severity.HIGH, category="x", file=file, line=line,
                    summary=summary, evidence="...", confidence=confidence, provider=provider)


def test_corroborates_nearby_findings_from_different_providers():
    findings = [
        _f("anthropic", "src/auth.py", 42, "Hardcoded bypass for debug_override user"),
        _f("mistral", "src/auth.py", 44, "Suspicious username comparison allows bypass", confidence="low"),
    ]
    cross_check(findings)
    assert all("confirmed independently by both anthropic and mistral" in f.summary for f in findings)
    assert all(f.confidence == "high" for f in findings)


def test_does_not_corroborate_far_apart_lines():
    findings = [
        _f("anthropic", "src/auth.py", 10, "issue A"),
        _f("mistral", "src/auth.py", 500, "issue B"),
    ]
    cross_check(findings)
    assert "confirmed independently" not in findings[0].summary
    assert "confirmed independently" not in findings[1].summary


def test_single_provider_finding_is_never_touched():
    findings = [_f("anthropic", "src/other.py", 10, "only one model saw this", confidence="low")]
    cross_check(findings)
    assert findings[0].summary == "only one model saw this"
    assert findings[0].confidence == "low"


def test_ignores_non_llm_findings():
    heuristic = Finding(scanner="secrets", severity=Severity.HIGH, category="hardcoded-secret",
                         file="a.py", line=1, summary="key found", confidence="high")
    findings = [heuristic]
    cross_check(findings)
    assert findings[0].summary == "key found"
