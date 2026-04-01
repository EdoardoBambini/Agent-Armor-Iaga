"""Type definitions for Agent Armor SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class GovernanceDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class ActionType(str, Enum):
    SHELL = "shell"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    HTTP = "http"
    DB_QUERY = "db_query"
    EMAIL = "email"
    CUSTOM = "custom"


class ReviewStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ActionDetail:
    type: ActionType
    tool_name: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "toolName": self.tool_name,
            "payload": self.payload,
        }


@dataclass
class InspectRequest:
    agent_id: str
    framework: str
    action: ActionDetail
    workspace_id: Optional[str] = None
    protocol: Optional[str] = None
    requested_secrets: Optional[list[str]] = None
    metadata: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "agentId": self.agent_id,
            "framework": self.framework,
            "action": self.action.to_dict(),
        }
        if self.workspace_id is not None:
            d["workspaceId"] = self.workspace_id
        if self.protocol is not None:
            d["protocol"] = self.protocol
        if self.requested_secrets is not None:
            d["requestedSecrets"] = self.requested_secrets
        if self.metadata is not None:
            d["metadata"] = self.metadata
        return d


@dataclass
class RiskScore:
    score: int
    decision: GovernanceDecision
    reasons: list[str]


@dataclass
class GovernanceResult:
    decision: GovernanceDecision
    review_status: ReviewStatus
    risk: RiskScore
    policy_findings: list[str]
    protocol: str
    review_request_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> GovernanceResult:
        risk_data = data.get("risk", {})
        return cls(
            decision=GovernanceDecision(data["decision"]),
            review_status=ReviewStatus(data.get("reviewStatus", "not_required")),
            risk=RiskScore(
                score=risk_data.get("score", 0),
                decision=GovernanceDecision(risk_data.get("decision", "block")),
                reasons=risk_data.get("reasons", []),
            ),
            policy_findings=data.get("policyFindings", []),
            protocol=data.get("protocol", "unknown"),
            review_request_id=data.get("reviewRequestId"),
        )

    @property
    def allowed(self) -> bool:
        return self.decision == GovernanceDecision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision == GovernanceDecision.BLOCK

    @property
    def needs_review(self) -> bool:
        return self.decision == GovernanceDecision.REVIEW
