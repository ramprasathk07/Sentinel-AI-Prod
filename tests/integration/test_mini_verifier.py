
import pytest
import json
from pathlib import Path
from agents.mini_verifier.agent import MiniVerifier

@pytest.mark.asyncio
async def test_homoglyph():
    mv = MiniVerifier()
    base = Path("f:\\\\Hackathons\\\\Sentinel-AI\\\\tests\\\\fixtures\\\\verifier\\\\homoglyph")
    finding = json.loads((base / "finding.json").read_text())
    
    # 1. Before vs Before (FAIL)
    res_bb = await mv.verify(finding, base/"before", base/"before")
    assert res_bb.shannon_verdict == "FAIL"
    
    # 2. Before vs After (PASS)
    res_ba = await mv.verify(finding, base/"before", base/"after")
    assert res_ba.shannon_verdict == "PASS"

@pytest.mark.asyncio
async def test_base64_payload():
    mv = MiniVerifier()
    base = Path("f:\\\\Hackathons\\\\Sentinel-AI\\\\tests\\\\fixtures\\\\verifier\\\\base64_payload")
    finding = json.loads((base / "finding.json").read_text())
    
    res_bb = await mv.verify(finding, base/"before", base/"before")
    assert res_bb.shannon_verdict == "FAIL"
    
    res_ba = await mv.verify(finding, base/"before", base/"after")
    assert res_ba.shannon_verdict == "PASS"

# We can add test_cve but it requires OSV API to be live.
