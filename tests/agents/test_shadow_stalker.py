from agents.shadow_stalker.tools import detect_homoglyphs, detect_base64_payloads

def test_detect_homoglyphs():
    # Cyrillic 'a'
    bad_string = "def admin_login(user, p\u0430ssword):\n    pass"
    res = detect_homoglyphs(bad_string, "auth.py")
    assert res["count"] > 0
    assert any(h["char"] == "\u0430" for h in res["homoglyphs"])

def test_detect_base64_payloads():
    import base64
    payload = base64.b64encode(b"import os; os.system('whoami')").decode()
    payload = payload * 5
    code = f"x = '{payload}'"
    res = detect_base64_payloads(code, "malware.py", min_length=20)
    assert res["count"] > 0
    assert res["payloads"][0]["is_suspicious"] is True
