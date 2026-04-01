export type GovernanceDecision = "allow" | "review" | "block";
export type ActionType = "shell" | "file_read" | "file_write" | "http" | "db_query" | "email" | "custom";
export type ReviewStatus = "not_required" | "pending" | "approved" | "rejected";
export type ProtocolKind = "mcp" | "acp" | "a2a" | "http-function" | "unknown";

export interface ActionDetail {
  type: ActionType;
  toolName: string;
  payload: Record<string, unknown>;
}

export interface InspectRequest {
  agentId: string;
  framework: string;
  action: ActionDetail;
  workspaceId?: string;
  protocol?: ProtocolKind;
  requestedSecrets?: string[];
  metadata?: Record<string, unknown>;
}

export interface RiskScore {
  score: number;
  decision: GovernanceDecision;
  reasons: string[];
}

export interface GovernanceResult {
  decision: GovernanceDecision;
  reviewStatus: ReviewStatus;
  risk: RiskScore;
  policyFindings: string[];
  protocol: ProtocolKind;
  reviewRequestId?: string;
  normalizedPayload: Record<string, unknown>;
  schemaValidation: {
    toolName: string;
    valid: boolean;
    findings: string[];
  };
  secretPlan: {
    approved: string[];
    denied: string[];
  };
}

export interface AuditEvent {
  eventId: string;
  agentId: string;
  framework: string;
  actionType: ActionType;
  toolName: string;
  decision: GovernanceDecision;
  timestamp: string;
  reasons: string[];
  reviewStatus: ReviewStatus;
  riskScore: number;
}

export interface ReviewRequest {
  id: string;
  agentId: string;
  workspaceId: string;
  toolName: string;
  decision: GovernanceDecision;
  status: string;
  riskScore: number;
  reasons: string[];
  createdAt: string;
  updatedAt: string;
}

export interface ArmorClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
}
