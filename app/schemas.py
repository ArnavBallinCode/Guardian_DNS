from __future__ import annotations
from pydantic import BaseModel, Field


# ── Auth ──────────────────────────────────────────────────────
class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=4, max_length=120)
    role: str = Field(pattern=r"^(reviewer|parent)$")
    display_name: str = Field(default="", max_length=60)


class SigninRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AuthUserResponse(BaseModel):
    id: int
    username: str
    role: str
    display_name: str


class SigninResponse(BaseModel):
    token: str
    user: AuthUserResponse


class ParentBlockRequest(BaseModel):
    domain: str = Field(min_length=1)
    category: str = Field(default="parent_blocked")


# ── Domain ────────────────────────────────────────────────────
class EvaluateRequest(BaseModel):
    domain: str = Field(min_length=1)
    category: str = Field(default="unknown")
    p_risk: float = Field(ge=0.0, le=1.0)


class AssessRequest(BaseModel):
    domain: str = Field(min_length=1)
    category_hint: str = Field(default="unknown")
    evidence_urls: list[str] = Field(default_factory=list)
    skip_context_fetch: bool = Field(default=False)


class AssessResponse(BaseModel):
    domain: str
    p_risk: float
    llm_category: str
    llm_rationale: str
    model_used: str
    action: str
    reason: str
    bypassable: bool
    review_required: bool
    combined_confidence: float | None = None


class EvaluateResponse(BaseModel):
    domain: str
    action: str
    reason: str
    bypassable: bool
    review_required: bool
    combined_confidence: float | None = None


class VoteRequest(BaseModel):
    domain: str = Field(min_length=1)
    reviewer_id: str = Field(min_length=1)
    agree: bool
    proof: str = Field(min_length=3, max_length=300)


class VoteResponse(BaseModel):
    domain: str
    votes: int
    p_vote: float
    p_risk: float
    combined_confidence: float
    permanently_blocked: bool


class ParentSummaryResponse(BaseModel):
    total_blocked: int
    by_category: dict[str, int]


class SetupActionRequest(BaseModel):
    service_name: str = Field(default="Wi-Fi", min_length=1)
    api_url: str = Field(default="http://127.0.0.1:8000", min_length=1)


class SetupActionResponse(BaseModel):
    success: bool
    exit_code: int
    stdout: str
    stderr: str
