from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class VulnerabilityType(str, Enum):
    SQL_INJECTION            = "SQL_INJECTION"
    PATH_TRAVERSAL           = "PATH_TRAVERSAL"
    COMMAND_INJECTION        = "COMMAND_INJECTION"
    SSRF                     = "SSRF"
    HARDCODED_SECRET         = "HARDCODED_SECRET"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    XXE                      = "XXE"
    OPEN_REDIRECT            = "OPEN_REDIRECT"
    XSS                      = "XSS"
    WEAK_CRYPTO              = "WEAK_CRYPTO"


class Finding(BaseModel):
    # extra='ignore' means unknown fields from LLM output are silently dropped
    # instead of raising a ValidationError — critical for robustness
    model_config = ConfigDict(extra="ignore")

    vuln_type:       VulnerabilityType
    severity:        Severity
    line_start:      int
    line_end:        int
    description:     str = Field(description="What is wrong and exactly why dangerous")
    triggering_input: str = Field(description="Exact user input that triggers this vuln")
    fix:             str  = Field(description="One-line code fix")
    confidence:      float = Field(ge=0.0, le=1.0)


class ReviewResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    findings:      list[Finding]
    summary:       str
    has_error:     bool = False
    error_message: Optional[str] = None


class AdjudicationResult(BaseModel):
    finding:       Finding
    correct_model: str   # "gemini" | "groq" | "both_wrong" | "both_right"
    reasoning:     str


class OrchestratorResult(BaseModel):
    # Agreed = both models found it = HIGH confidence
    agreed_findings:      list[Finding]
    # Adjudicated = disagreement resolved = MEDIUM confidence
    adjudicated_findings: list[Finding]
    # Sole = only one model, adjudication disagreed = LOW confidence
    sole_findings:        list[Finding]
    gemini_raw:           ReviewResult
    groq_raw:             ReviewResult
    total_findings:       int
    @property
    def has_error(self) -> bool:
        return self.gemini_raw.has_error or self.groq_raw.has_error

class TestCase(BaseModel):
    input_value: str
    attack_type: str
    description: str


class ExploitProof(BaseModel):
    input_used:          str
    actual_output:       str
    confirmed:           bool
    exploit_description: str
    attack_type:         str


class Z3PropertyJSON(BaseModel):
    """
    Intermediate representation between LLM and Z3.
    LLM generates this JSON. Python converts it to Z3 code deterministically.
    Never ask the LLM to write Z3 code directly — too many syntax errors.
    """
    model_config = ConfigDict(extra="ignore")
    property_name: str
    property_type: str   # "no_overflow"|"array_bounds"|"null_safety"|"division_by_zero"|"invariant"
    variables:     list[dict]   # [{"name":"x","type":"int","min":-2147483648,"max":2147483647}]
    constraints:   list[str]    # ["x > 0", "y < 100"]
    assertion:     str          # "result < 2147483647"


class Z3Result(BaseModel):
    property_name:   str
    status:          str   # "PROVED"|"COUNTEREXAMPLE"|"TIMEOUT"|"ERROR"
    counterexample:  Optional[dict] = None
    human_readable:  str


class VulnNode(BaseModel):
    id:          str
    vuln_type:   VulnerabilityType
    severity:    Severity
    location:    str
    description: str


class ChainLink(BaseModel):
    from_id:    str
    to_id:      str
    edge_type:  str   # "ENABLES"|"AMPLIFIES"|"PREREQUISITE"
    explanation: str


class ChainResult(BaseModel):
    chain:             list[VulnNode]
    links:             list[ChainLink]
    narrative:         str
    combined_severity: Severity


class AIDetectionResult(BaseModel):
    ai_probability:   float = Field(ge=0.0, le=1.0)
    structural_score: float
    pattern_score:    float
    matched_patterns: list[str]
    routing:          str   # "FULL"|"MEDIUM"|"SKIP"
