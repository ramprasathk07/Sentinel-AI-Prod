from agents.archeologist.tools import query_osv, parse_lockfile

def test_query_osv():
    # Test a known vulnerable package
    res = query_osv("requests", "2.6.0", "PyPI")
    assert "requests" in res["package"]
    assert res["count"] > 0
    assert any(vuln["cve_id"] for vuln in res["vulnerabilities"])

def test_parse_lockfile():
    # Test requirements.txt
    reqs = "requests==2.6.0\nflask>=1.0\n"
    res = parse_lockfile(reqs, "requirements.txt")
    assert res["count"] == 2
    deps = res["dependencies"]
    assert any(d["name"] == "requests" and d["version"] == "2.6.0" for d in deps)
