"""Sync and async HTTP clients for Agent Armor API."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .types import GovernanceResult, InspectRequest


class AsyncArmorClient:
    """Async client for Agent Armor governance API (httpx-based)."""

    def __init__(
        self,
        base_url: str = "http://localhost:4010",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def inspect(self, request: InspectRequest) -> GovernanceResult:
        """Submit an action for governance inspection."""
        resp = await self._client.post("/v1/inspect", json=request.to_dict())
        resp.raise_for_status()
        return GovernanceResult.from_dict(resp.json())

    async def list_audit(self) -> list[dict[str, Any]]:
        """List recent audit events."""
        resp = await self._client.get("/v1/audit")
        resp.raise_for_status()
        return resp.json()

    async def list_reviews(self) -> list[dict[str, Any]]:
        """List pending review requests."""
        resp = await self._client.get("/v1/reviews")
        resp.raise_for_status()
        return resp.json()

    async def resolve_review(self, review_id: str, status: str) -> dict[str, Any]:
        """Approve or reject a review request."""
        resp = await self._client.post(
            f"/v1/reviews/{review_id}", json={"status": status}
        )
        resp.raise_for_status()
        return resp.json()

    async def health(self) -> dict[str, Any]:
        """Check server health."""
        resp = await self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


class ArmorClient:
    """Sync client for Agent Armor governance API (httpx-based)."""

    def __init__(
        self,
        base_url: str = "http://localhost:4010",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    def inspect(self, request: InspectRequest) -> GovernanceResult:
        """Submit an action for governance inspection."""
        resp = self._client.post("/v1/inspect", json=request.to_dict())
        resp.raise_for_status()
        return GovernanceResult.from_dict(resp.json())

    def list_audit(self) -> list[dict[str, Any]]:
        """List recent audit events."""
        resp = self._client.get("/v1/audit")
        resp.raise_for_status()
        return resp.json()

    def list_reviews(self) -> list[dict[str, Any]]:
        """List pending review requests."""
        resp = self._client.get("/v1/reviews")
        resp.raise_for_status()
        return resp.json()

    def resolve_review(self, review_id: str, status: str) -> dict[str, Any]:
        """Approve or reject a review request."""
        resp = self._client.post(
            f"/v1/reviews/{review_id}", json={"status": status}
        )
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict[str, Any]:
        """Check server health."""
        resp = self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
