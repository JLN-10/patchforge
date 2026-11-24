import pytest
from patchforge.scanner import CodeScanner
from patchforge.patcher import PatchAgent
from patchforge.validator import SandboxValidator
from patchforge.models import VulnerabilityType

SAMPLE_VULN_CODE = """import os
def ping_server(host):
    os.system(f"ping -c 1 {host}")
"""

def test_code_scanner_detects_command_injection(tmp_path):
    test_file = tmp_path / "app.py"
    test_file.write_text(SAMPLE_VULN_CODE, encoding="utf-8")

    scanner = CodeScanner()
    issues = scanner.scan_file(str(test_file))

    assert len(issues) == 1
    assert issues[0].vuln_type == VulnerabilityType.COMMAND_INJECTION

def test_patch_agent_and_sandbox_validation():
    scanner = CodeScanner()
    patcher = PatchAgent()
    validator = SandboxValidator()

    # Create temporary file
    lines = SAMPLE_VULN_CODE.splitlines()
    issue = scanner.scan_file.__func__(None, "") # mock call structure
    
    # Direct patch test
    import re
    from patchforge.models import VulnerabilityIssue, Severity
    dummy_issue = VulnerabilityIssue(
        id="test:L3",
        file_path="app.py",
        line_number=3,
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.HIGH,
        description="os.system call",
        code_snippet="os.system(f\"ping -c 1 {host}\")",
        remediation_advice="use subprocess"
    )

    patch = patcher.generate_patch(dummy_issue, SAMPLE_VULN_CODE)
    assert "subprocess.run" in patch.patched_code
    assert "os.system" not in patch.patched_code

    validation = validator.validate_patch(patch)
    assert validation.security_check_passed is True
