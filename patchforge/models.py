from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class VulnerabilityType(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    HARDCODED_SECRET = "hardcoded_secret"
    PATH_TRAVERSAL = "path_traversal"

class VulnerabilityIssue(BaseModel):
    id: str
    file_path: str
    line_number: int
    vuln_type: VulnerabilityType
    severity: Severity
    description: str
    code_snippet: str
    remediation_advice: str

class PatchResult(BaseModel):
    issue_id: str
    file_path: str
    original_code: str
    patched_code: str
    diff: str
    explanation: str

class ValidationResult(BaseModel):
    issue_id: str
    tests_passed: bool
    security_check_passed: bool
    sandbox_output: str
    errors: Optional[str] = None
