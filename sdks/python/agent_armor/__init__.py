"""IAGA Agent Armor SDK — Zero-trust governance for autonomous AI agents."""

from .client import ArmorClient, AsyncArmorClient
from .types import (
    InspectRequest,
    ActionDetail,
    GovernanceResult,
    GovernanceDecision,
)
from .decorator import governed

__version__ = "0.1.0"
__all__ = [
    "ArmorClient",
    "AsyncArmorClient",
    "InspectRequest",
    "ActionDetail",
    "GovernanceResult",
    "GovernanceDecision",
    "governed",
]
