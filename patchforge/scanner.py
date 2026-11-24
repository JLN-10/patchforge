import ast
import os
import re
from pathlib import Path
from typing import List
from patchforge.models import VulnerabilityIssue, VulnerabilityType, Severity

class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.issues: List[VulnerabilityIssue] = []

    def visit_Call(self, node: ast.Call):
        # 1. Detect os.system / subprocess.Popen with shell=True
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name == "system":
            line = node.lineno
            snippet = self.lines[line - 1] if line <= len(self.lines) else ""
            self.issues.append(VulnerabilityIssue(
                id=f"{os.path.basename(self.file_path)}:L{line}:cmd_inj",
                file_path=self.file_path,
                line_number=line,
                vuln_type=VulnerabilityType.COMMAND_INJECTION,
                severity=Severity.HIGH,
                description="Use of os.system() can lead to command injection if unvalidated input is passed.",
                code_snippet=snippet,
                remediation_advice="Use subprocess.run() with shell=False and pass arguments as an explicit list."
            ))

        # 2. Detect execute() with string formatting / f-strings (SQL injection)
        if func_name in ("execute", "executemany"):
            if node.args:
                arg0 = node.args[0]
                is_dangerous_str = False
                if isinstance(arg0, ast.JoinedStr): # f-string
                    is_dangerous_str = True
                elif isinstance(arg0, ast.BinOp) and isinstance(arg0.op, ast.Mod): # "..." % var
                    is_dangerous_str = True
                elif isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute) and arg0.func.attr == "format":
                    is_dangerous_str = True

                if is_dangerous_str:
                    line = node.lineno
                    snippet = self.lines[line - 1] if line <= len(self.lines) else ""
                    self.issues.append(VulnerabilityIssue(
                        id=f"{os.path.basename(self.file_path)}:L{line}:sqli",
                        file_path=self.file_path,
                        line_number=line,
                        vuln_type=VulnerabilityType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        description="Raw query concatenation detected in DB execute() call (SQL Injection risk).",
                        code_snippet=snippet,
                        remediation_advice="Use parameterized queries with placeholder bindings (e.g. cursor.execute('SELECT ... WHERE id = ?', (id,)))."
                    ))

        # 3. Detect pickle.loads / pickle.load
        if func_name in ("loads", "load"):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                line = node.lineno
                snippet = self.lines[line - 1] if line <= len(self.lines) else ""
                self.issues.append(VulnerabilityIssue(
                    id=f"{os.path.basename(self.file_path)}:L{line}:pickle",
                    file_path=self.file_path,
                    line_number=line,
                    vuln_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                    severity=Severity.HIGH,
                    description="Insecure deserialization using pickle.load() can lead to arbitrary code execution.",
                    code_snippet=snippet,
                    remediation_advice="Use safe serialization formats like json or safetensors."
                ))

        self.generic_visit(node)

class CodeScanner:
    """Recursively scans Python codebases for security vulnerabilities using AST and regex."""
    def scan_file(self, file_path: str) -> List[VulnerabilityIssue]:
        issues: List[VulnerabilityIssue] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return issues

        # Check for hardcoded secrets via regex
        secret_patterns = [
            (r'(?i)(api[_-]?key|secret|password|access[_-]?token)\s*=\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "Hardcoded API secret/key detected.")
        ]
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            for pat, desc in secret_patterns:
                if re.search(pat, line):
                    issues.append(VulnerabilityIssue(
                        id=f"{os.path.basename(file_path)}:L{idx+1}:secret",
                        file_path=file_path,
                        line_number=idx + 1,
                        vuln_type=VulnerabilityType.HARDCODED_SECRET,
                        severity=Severity.CRITICAL,
                        description=desc,
                        code_snippet=line,
                        remediation_advice="Retrieve credentials from environment variables (os.environ or pydantic BaseSettings)."
                    ))

        # AST analysis
        try:
            tree = ast.parse(content, filename=file_path)
            visitor = SecurityASTVisitor(file_path, content)
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except SyntaxError:
            pass

        return issues

    def scan_directory(self, dir_path: str) -> List[VulnerabilityIssue]:
        all_issues = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    all_issues.extend(self.scan_file(full_path))
        return all_issues
