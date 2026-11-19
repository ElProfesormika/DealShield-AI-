from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field

UserRole = Literal["analyst", "partner"]
Severity = Literal["Critique", "Modéré", "À vérifier"]


class DocumentInput(BaseModel):
    name: str = Field(..., description="Nom du fichier dans la Data Room")
    content: str = Field(..., description="Contenu textuel du document")


class AnalyzeRequest(BaseModel):
    user_role: UserRole = Field(default="analyst", description="Rôle RBAC du consultant")
    documents: List[DocumentInput] = Field(..., min_length=1)


class ChatRequest(BaseModel):
    user_role: UserRole = Field(default="analyst")
    question: str = Field(..., min_length=1)
    documents: List[DocumentInput] = Field(default_factory=list)
    red_flags_summary: Optional[str] = None


class ExtractedItem(BaseModel):
    doc_name: str
    page: str = "Page 1"
    label: str
    excerpt: str


class ChatResponse(BaseModel):
    answer: str
    extracted_items: List[ExtractedItem] = Field(default_factory=list)
    blocked_by_security: bool = False
    security_reason: Optional[str] = None
    mode: Literal["gemini_live", "deterministic_engine"]


class ConfigRequest(BaseModel):
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"
    gcp_project_id: str = "deloitteinnov26par-599"


class SecurityEvent(BaseModel):
    doc_name: str
    event_type: Literal["PROMPT_INJECTION_BLOCKED", "DLP_PII_REDACTED", "RBAC_RESTRICTED"]
    severity: Literal["HIGH", "MEDIUM", "INFO"]
    details: str
    neutralized_payload: Optional[str] = None


class SanitizedDocument(BaseModel):
    doc_name: str
    original_preview: str
    sanitized_content: str
    threat_score: int = Field(ge=0, le=100)
    blocked_injections: int = 0
    redacted_entities: int = 0


class RedFlag(BaseModel):
    id: str
    doc_name: str
    page: str
    category: str
    severity: Severity
    title: str
    description: str
    excerpt: str
    financial_impact_eur: Optional[float] = None


class FinancialCheck(BaseModel):
    metric: str
    status: Literal["ALERT", "OK", "WARNING"]
    computed_value: str
    threshold_or_expected: str
    explanation: str


class ToolTrace(BaseModel):
    step: int
    tool_name: str
    status: Literal["SUCCESS", "WARNING", "BLOCKED_THREAT"]
    duration_ms: float
    thought: str
    summary: str
    observation: str
    details: Dict[str, Any] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    agent_name: str = "DealShield AI"
    mode: Literal["gemini_live", "deterministic_engine"]
    user_role: UserRole
    overall_threat_score: int
    documents_scanned: int
    injections_blocked: int
    pii_redacted: int
    sanitized_documents: List[SanitizedDocument]
    security_events: List[SecurityEvent]
    red_flags: List[RedFlag]
    financial_checks: List[FinancialCheck]
    executive_memo_markdown: str
    tool_traces: List[ToolTrace]
