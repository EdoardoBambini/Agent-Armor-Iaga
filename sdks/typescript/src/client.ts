import type {
  ArmorClientOptions,
  AuditEvent,
  GovernanceResult,
  InspectRequest,
  ReviewRequest,
} from "./types";

export class ArmorClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;

  constructor(options: ArmorClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "http://localhost:4010").replace(/\/$/, "");
    this.timeout = options.timeout ?? 10000;
    this.headers = { "Content-Type": "application/json" };
    if (options.apiKey) {
      this.headers["Authorization"] = `Bearer ${options.apiKey}`;
    }
  }

  async inspect(request: InspectRequest): Promise<GovernanceResult> {
    const resp = await this.fetch("/v1/inspect", {
      method: "POST",
      body: JSON.stringify(request),
    });
    return resp as GovernanceResult;
  }

  async listAudit(): Promise<AuditEvent[]> {
    return this.fetch("/v1/audit") as Promise<AuditEvent[]>;
  }

  async listReviews(): Promise<ReviewRequest[]> {
    return this.fetch("/v1/reviews") as Promise<ReviewRequest[]>;
  }

  async resolveReview(
    reviewId: string,
    status: "approved" | "rejected"
  ): Promise<ReviewRequest> {
    return this.fetch(`/v1/reviews/${reviewId}`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }) as Promise<ReviewRequest>;
  }

  async health(): Promise<{ ok: boolean; service: string; mode: string }> {
    return this.fetch("/health") as Promise<any>;
  }

  /**
   * Subscribe to real-time governance events via SSE.
   * Returns an EventSource instance.
   */
  eventStream(): EventSource {
    const url = `${this.baseUrl}/v1/events/stream`;
    return new EventSource(url);
  }

  private async fetch(path: string, init?: RequestInit): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await globalThis.fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: { ...this.headers, ...(init?.headers as Record<string, string>) },
        signal: controller.signal,
      });

      if (!resp.ok) {
        const body = await resp.text().catch(() => "");
        throw new ArmorApiError(resp.status, body, path);
      }

      return resp.json();
    } finally {
      clearTimeout(timer);
    }
  }
}

export class ArmorApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    public readonly path: string
  ) {
    super(`Agent Armor API error ${status} on ${path}: ${body}`);
    this.name = "ArmorApiError";
  }
}

/**
 * Governance wrapper: checks a tool call before execution.
 * Throws ArmorBlockedError if blocked or needs review.
 */
export async function governed<T>(
  client: ArmorClient,
  request: InspectRequest,
  fn: () => T | Promise<T>
): Promise<T> {
  const result = await client.inspect(request);

  if (result.decision === "block") {
    throw new ArmorBlockedError(result);
  }
  if (result.decision === "review") {
    throw new ArmorReviewError(result);
  }

  return fn();
}

export class ArmorBlockedError extends Error {
  constructor(public readonly result: GovernanceResult) {
    super(
      `Tool '${result.risk.reasons.join(", ")}' blocked by Agent Armor (risk: ${result.risk.score})`
    );
    this.name = "ArmorBlockedError";
  }
}

export class ArmorReviewError extends Error {
  constructor(public readonly result: GovernanceResult) {
    super(
      `Tool requires review (reviewId: ${result.reviewRequestId}, risk: ${result.risk.score})`
    );
    this.name = "ArmorReviewError";
  }
}
