"""Unified security research and bug-bounty platform.

This project fuses the strongest ideas from the Bug-Bounty-Agents and SecBrain
repositories into a single, maintainable security platform focused on evidence,
authorization, and structured agent routing.
"""

from .agents import AgentRegistry, AgentSpec, route_agent
from .assessment import AssessmentEngine, AssessmentResult
from .config import ScopeConfig, SecurityAppConfig
from .engagement import AuthIdentity, Engagement
from .findings import Finding, FindingStore
from .http_client import HttpClient, HttpResponse
from .investigation import InvestigationMemory
from .safety import SafetyPolicy
from .workspace import ExecutionHistory

__all__ = [
    "AgentRegistry",
    "AgentSpec",
    "AssessmentEngine",
    "AssessmentResult",
    "AuthIdentity",
    "Engagement",
    "ExecutionHistory",
    "Finding",
    "FindingStore",
    "HttpClient",
    "HttpResponse",
    "InvestigationMemory",
    "ScopeConfig",
    "SecurityAppConfig",
    "SafetyPolicy",
    "route_agent",
]

__version__ = "0.1.0"
