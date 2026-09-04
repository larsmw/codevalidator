from codevalidator.diff_heuristics import check_test_tampering

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
