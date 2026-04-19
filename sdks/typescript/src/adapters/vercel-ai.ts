import { ArmorBlockedError, ArmorClient, ArmorReviewError } from "../client";
import type { ArmorMiddlewareOptions, InspectRequest, JsonObject } from "../types";

function buildInspectRequest(
  options: ArmorMiddlewareOptions,
  payload: JsonObject
): InspectRequest {
  return {
    agentId: options.agentId,
    tenantId: options.tenantId,
    workspaceId: options.workspaceId,
    framework: options.framework ?? "vercel-ai",
    sessionId: options.sessionId,
    metadata: options.metadata,
    action: {
      type: options.actionType ?? "http",
      toolName: options.toolName ?? "vercel-ai.generate",
      payload,
    },
  };
}

async function inspectPayload(
  client: ArmorClient,
  options: ArmorMiddlewareOptions,
  payload: JsonObject
): Promise<void> {
  const result = await client.inspect(buildInspectRequest(options, payload));
  if (result.decision === "block") {
    throw new ArmorBlockedError(result);
  }
  if (result.decision === "review") {
    throw new ArmorReviewError(result);
  }
}

export function armorMiddleware(options: ArmorMiddlewareOptions) {
  const client = new ArmorClient(options);

  return {
    name: "agent-armor",
    async inspect(payload: JsonObject): Promise<void> {
      await inspectPayload(client, options, payload);
    },
    async wrapGenerate<T>(
      next: (payload: JsonObject) => Promise<T>,
      payload: JsonObject
    ): Promise<T> {
      await inspectPayload(client, options, payload);
      return next(payload);
    },
    async wrapStream<T>(
      next: (payload: JsonObject) => Promise<T>,
      payload: JsonObject
    ): Promise<T> {
      await inspectPayload(client, options, payload);
      return next(payload);
    },
  };
}
