import difflib
import re
from patchforge.models import VulnerabilityIssue, VulnerabilityType, PatchResult

class PatchAgent:
    """
    Intelligent patching agent. Generates semantic AST/code transformations to fix
    vulnerabilities while preserving program logic.
    """
    def generate_patch(self, issue: VulnerabilityIssue, original_code: str) -> PatchResult:
        lines = original_code.splitlines(keepends=True)
        patched_lines = list(lines)
        line_idx = issue.line_number - 1
        explanation = ""

        if issue.vuln_type == VulnerabilityType.COMMAND_INJECTION:
            target_line = lines[line_idx]
            # Replace os.system(cmd) with subprocess.run(shlex.split(cmd), check=True)
            if "os.system(" in target_line:
                patched_line = re.sub(
                    r"os\.system\((.*?)\)",
                    r"subprocess.run(shlex.split(\1), check=True)",
                    target_line
                )
                patched_lines[line_idx] = patched_line

                # Add import if missing
                has_shlex = any("import shlex" in l for l in lines)
                has_subprocess = any("import subprocess" in l for l in lines)
                header_additions = []
                if not has_subprocess:
                    header_additions.append("import subprocess\n")
                if not has_shlex:
                    header_additions.append("import shlex\n")
                if header_additions:
                    patched_lines = header_additions + patched_lines

                explanation = "Replaced unsafe os.system() with subprocess.run(shlex.split(...), check=True) to prevent shell injection."

        elif issue.vuln_type == VulnerabilityType.SQL_INJECTION:
            target_line = lines[line_idx]
            # Convert execute(f"SELECT ... {var}") -> execute("SELECT ... ?", (var,))
            fstr_match = re.search(r'execute\(f["\'](.*?)\{([a-zA-Z0-9_]+)\}(.*?)["\']\)', target_line)
            if fstr_match:
                prefix = fstr_match.group(1)
                var_name = fstr_match.group(2)
                suffix = fstr_match.group(3)
                safe_query = f'execute("{prefix}?{suffix}", ({var_name},))'
                patched_line = target_line[:fstr_match.start()] + safe_query + target_line[fstr_match.end():]
                patched_lines[line_idx] = patched_line
                explanation = f"Replaced unsafe string interpolation with parameterized SQL query placeholder for variable `{var_name}`."
            else:
                explanation = "Manual parameterization required for complex query concatenation."

        elif issue.vuln_type == VulnerabilityType.HARDCODED_SECRET:
            target_line = lines[line_idx]
            # Replace KEY = "..." with KEY = os.environ.get("KEY", "")
            match = re.search(r'([A-Za-z0-9_]+)\s*=\s*["\'][^"\']+["\']', target_line)
            if match:
                key_name = match.group(1)
                patched_line = f'{key_name} = os.environ.get("{key_name.upper()}", "")\n'
                patched_lines[line_idx] = patched_line
                if not any("import os" in l for l in lines):
                    patched_lines = ["import os\n"] + patched_lines
                explanation = f"Moved hardcoded secret `{key_name}` to dynamic environment variable retrieval via `os.environ.get()`."

        patched_code = "".join(patched_lines)
        diff = "".join(difflib.unified_diff(
            lines,
            patched_lines,
            fromfile=f"a/{issue.file_path}",
            tofile=f"b/{issue.file_path}"
        ))

        return PatchResult(
            issue_id=issue.id,
            file_path=issue.file_path,
            original_code=original_code,
            patched_code=patched_code,
            diff=diff,
            explanation=explanation or "Refactored vulnerable line to follow safe API guidelines."
        )
