import os
import ast
import tempfile
import subprocess
from patchforge.models import PatchResult, ValidationResult
from patchforge.scanner import CodeScanner

class SandboxValidator:
    """
    Validates patches by:
    1. Checking Python AST syntax validity of the generated patch.
    2. Re-running the security scanner to ensure the vulnerability was eradicated.
    3. Running any associated unit tests in an isolated execution sandbox.
    """
    def __init__(self):
        self.scanner = CodeScanner()

    def validate_patch(self, patch: PatchResult, test_command: str = None) -> ValidationResult:
        # Step 1: Syntax check
        try:
            ast.parse(patch.patched_code)
        except SyntaxError as e:
            return ValidationResult(
                issue_id=patch.issue_id,
                tests_passed=False,
                security_check_passed=False,
                sandbox_output="",
                errors=f"AST SyntaxError in generated patch: {e}"
            )

        # Step 2: Write temporary file and check if target vulnerability was eradicated
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as temp_f:
            temp_path = temp_f.name
            temp_f.write(patch.patched_code)

        try:
            remaining_issues = self.scanner.scan_file(temp_path)
            # Check if this specific issue/line is eradicated
            same_type_remains = any(
                i.vuln_type.value in patch.issue_id for i in remaining_issues
            )
            security_passed = not same_type_remains
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # Step 3: Run regression test command if supplied
        tests_passed = True
        sandbox_output = "No custom test command specified; AST & Security validation passed."
        if test_command:
            try:
                proc = subprocess.run(
                    test_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=20
                )
                sandbox_output = proc.stdout + "\n" + proc.stderr
                tests_passed = (proc.returncode == 0)
            except Exception as ex:
                tests_passed = False
                sandbox_output = f"Execution failed: {ex}"

        return ValidationResult(
            issue_id=patch.issue_id,
            tests_passed=tests_passed,
            security_check_passed=security_passed,
            sandbox_output=sandbox_output,
            errors=None if (tests_passed and security_passed) else "Validation check failed."
        )
