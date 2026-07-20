import urllib.request
import urllib.error
import json
import sys
import time

BASE_URL = "http://localhost:8080"  # Direct gateway port or port-forward target

def run_test(name, test_func):
    print(f"[*] Test: {name:<40}", end="", flush=True)
    try:
        test_func()
        print("[\033[92mPASS\033[0m]")
    except AssertionError as e:
        print(f"[\033[91mFAIL\033[0m] (Assertion: {e})")
    except Exception as e:
        print(f"[\033[91mFAIL\033[0m] (Error: {e})")

# ─── 1. Wrong Username/Password ──────────────────────────────────────────────
def test_wrong_credentials():
    url = f"{BASE_URL}/auth/token"
    data = urllib.parse.urlencode({"username": "admin", "password": "wrong_password"}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with urllib.request.urlopen(req) as resp:
            raise AssertionError("Login succeeded with incorrect credentials")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected HTTP 401, got {e.code}"

# ─── 2. SQL Injection Test ──────────────────────────────────────────────────
def test_sql_injection():
    # Attempt SQL injection payload on username field
    url = f"{BASE_URL}/auth/token"
    payload = "' OR '1'='1"
    data = urllib.parse.urlencode({"username": payload, "password": "wrong_password"}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with urllib.request.urlopen(req) as resp:
            raise AssertionError("Login vulnerable to SQL Injection bypass")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected HTTP 401 (Unauthorized), got {e.code}"

# ─── 3. Long Input Test ─────────────────────────────────────────────────────
def test_long_input():
    url = f"{BASE_URL}/auth/token"
    long_username = "A" * 10000
    data = urllib.parse.urlencode({"username": long_username, "password": "password"}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with urllib.request.urlopen(req) as resp:
            raise AssertionError("Accepted excessively long input without error")
    except urllib.error.HTTPError as e:
        # Standard input validation or failed login (either is safe, shouldn't crash)
        assert e.code in [401, 422], f"Expected HTTP 401 or 422, got {e.code}"

# ─── 4. Special Characters Test ──────────────────────────────────────────────
def test_special_characters():
    url = f"{BASE_URL}/auth/token"
    special_username = "admin!@#$%^&*()_+=-`~[]\\{}|;':\",./<>?"
    data = urllib.parse.urlencode({"username": special_username, "password": "password"}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with urllib.request.urlopen(req) as resp:
            raise AssertionError("Accepted invalid special character username")
    except urllib.error.HTTPError as e:
        assert e.code in [401, 422], f"Expected HTTP 401 or 422, got {e.code}"

# ─── 5. Direct URL Authorization Bypass ─────────────────────────────────────
def test_authorization_bypass():
    url = f"{BASE_URL}/api/v1/campaigns"
    req = urllib.request.Request(url, method="GET")
    
    try:
        with urllib.request.urlopen(req) as resp:
            raise AssertionError("Bypassed authorization checks")
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected HTTP 401 Unauthorized, got {e.code}"

# ─── 6. Cookie & Session Security ───────────────────────────────────────────
def test_session_cookie_isolation():
    # Attempt login to grab a token
    url = f"{BASE_URL}/auth/token"
    data = urllib.parse.urlencode({"username": "admin", "password": "netraai2026"}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    try:
        with urllib.request.urlopen(req) as resp:
            headers = resp.info()
            assert "Set-Cookie" not in headers, "Cookie detected: Authentication must be token-based, not session-cookie based."
    except urllib.error.HTTPError as e:
        # If rate limited, bypass this step
        if e.code == 429:
            print(" (Skipped: Login endpoint rate-limited) ", end="")
            return
        raise e

# ─── 7. Security Headers ────────────────────────────────────────────────────
def test_security_headers():
    url = f"{BASE_URL}/"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as resp:
        headers = resp.info()
        assert headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options: DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff", "Missing X-Content-Type-Options: nosniff"
        assert headers.get("Referrer-Policy") == "no-referrer", "Missing Referrer-Policy: no-referrer"
        assert "Content-Security-Policy" in headers, "Missing Content-Security-Policy header"
        assert headers.get("Server") == "NetraAI-Gateway", "Server fingerprint header still leaking uvicorn banner"

# ─── 8. Brute Force Protection ──────────────────────────────────────────────
def test_brute_force_protection():
    url = f"{BASE_URL}/auth/token"
    data = urllib.parse.urlencode({"username": "admin", "password": "bad_password"}).encode()
    
    # Send multiple sequential invalid login attempts
    limit_hit = False
    for i in range(10):
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 429:
                limit_hit = True
                break
    assert limit_hit, "Rate limiting / brute force protection did not block rapid login attempts"


if __name__ == "__main__":
    print("=" * 60)
    print("           NetraAI Automated Security Test Suite")
    print("=" * 60)
    
    run_test("Wrong Username/Password Verification", test_wrong_credentials)
    run_test("SQL Injection Prevention", test_sql_injection)
    run_test("Long Input Boundary Validation", test_long_input)
    run_test("Special Characters Sanitization", test_special_characters)
    run_test("Direct URL Auth Bypass Prevention", test_authorization_bypass)
    run_test("Session Cookie Exposure Protection", test_session_cookie_isolation)
    run_test("HTTP Security Headers Audit", test_security_headers)
    run_test("Login Brute-Force Rate Limiting", test_brute_force_protection)
    
    print("=" * 60)
