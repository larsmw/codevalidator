import subprocess

import pytest

from codevalidator.diff_heuristics import check_author_anomaly, check_test_tampering

_REMOVED_ASSERTION_WITH_PROD_CHANGE = '''diff --git a/tests/test_auth.py b/tests/test_auth.py
index 111..222 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -10,7 +10,6 @@ def test_login_rejects_bad_password():
     user = create_user("alice", "correct-horse")
     result = login("alice", "wrong-password")
-    assert result.success is False
     assert result.status_code == 401
diff --git a/src/auth.py b/src/auth.py
index 333..444 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -20,7 +20,7 @@ def login(username, password):
     user = find_user(username)
-    if not check_password(user, password):
+    if not check_password(user, password) or username == "debug_override":
         return LoginResult(success=False, status_code=401)
     return LoginResult(success=True)
'''

_SKIPPED_TEST_ONLY = '''diff --git a/tests/test_math.py b/tests/test_math.py
index 111..222 100644
--- a/tests/test_math.py
+++ b/tests/test_math.py
@@ -5,6 +5,7 @@ def test_add():
     assert add(1, 2) == 3
+@pytest.mark.skip(reason="flaky")
 def test_subtract():
     assert subtract(5, 2) == 3
'''

_CLEAN_NON_TEST_DIFF = '''diff --git a/src/util.py b/src/util.py
index 111..222 100644
--- a/src/util.py
+++ b/src/util.py
@@ -1,3 +1,3 @@
-def add(a, b):
+def add(a, b):  # fixed typo
     return a + b
'''


def test_flags_removed_assertion_as_high_when_prod_code_also_changes():
    findings = check_test_tampering(_REMOVED_ASSERTION_WITH_PROD_CHANGE)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "test-weakened"
    assert f.severity.name == "HIGH"
    assert f.file == "tests/test_auth.py"
    assert f.line == 12


def test_flags_skipped_test_as_medium_when_test_only():
    findings = check_test_tampering(_SKIPPED_TEST_ONLY)
    assert len(findings) == 1
    assert findings[0].category == "test-skipped"
    assert findings[0].severity.name == "MEDIUM"


def test_ignores_clean_non_test_diff():
    assert check_test_tampering(_CLEAN_NON_TEST_DIFF) == []


def test_ignores_empty_diff():
    assert check_test_tampering("") == []


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def _init_repo(repo, author_name, author_email):
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", author_name)
    _git(repo, "config", "user.email", author_email)


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    _init_repo(repo, "Alice", "alice@example.com")
    (repo / "src").mkdir()
    (repo / "src" / "auth.py").write_text("def login():\n    pass\n")
    (repo / "src" / "util.py").write_text("def helper():\n    pass\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial auth by alice")
    return repo


def test_author_anomaly_flags_unfamiliar_author_on_sensitive_file(git_repo):
    _git(git_repo, "config", "user.name", "Mallory")
    _git(git_repo, "config", "user.email", "mallory@example.com")
    (git_repo / "src" / "auth.py").write_text("def login():\n    return True  # backdoor\n")

    findings = check_author_anomaly(git_repo, "HEAD")
    assert len(findings) == 1
    assert findings[0].category == "unfamiliar-author-sensitive-path"
    assert findings[0].file == "src/auth.py"
    assert "mallory@example.com" in findings[0].summary


def test_author_anomaly_ignores_familiar_author(git_repo):
    (git_repo / "src" / "auth.py").write_text("def login():\n    return True\n")  # still alice
    assert check_author_anomaly(git_repo, "HEAD") == []


def test_author_anomaly_ignores_non_sensitive_file(git_repo):
    _git(git_repo, "config", "user.name", "Mallory")
    _git(git_repo, "config", "user.email", "mallory@example.com")
    (git_repo / "src" / "util.py").write_text("def helper():\n    return 42\n")
    assert check_author_anomaly(git_repo, "HEAD") == []
