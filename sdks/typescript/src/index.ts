export { ArmorClient, ArmorApiError, ArmorBlockedError, ArmorReviewError, governed } from "./client";
export { armorWrapOpenAI } from "./adapters/openai";
export { armorMiddleware } from "./adapters/vercel-ai";
export type {
  ActionDetail,
  ActionType,
  ArmorClientOptions,
  ArmorMiddlewareOptions,
  AuditEvent,
  GovernanceDecision,
  GovernanceResult,
  HealthResponse,
  InspectRequest,
  JsonObject,
  JsonValue,
  OpenAIAdapterOptions,
  PluginOutput,
  PluginResult,
  ProtocolKind,
  ReviewRequest,
  ReviewStatus,
} from "./types";
