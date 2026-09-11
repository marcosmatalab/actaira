"""Agents, tools and MCP servers as things with versions, digests and limits.

Design note D-140. In 2026 the thing an organisation deploys is not a model.
It is an agent: a model, a system prompt, a set of tools, some MCP servers it
dials, credentials it holds, and data it can reach. Every one of those is a
supply-chain component with its own publisher and its own version, and none of
them are visible to a scanner that looks at weight files.

The gap this closes is not "the tool does not scan agents". It is that the
interesting risk in an agent is not in any component. It is in the
combination: a tool that reads untrusted text next to a tool that sends email,
a credential with write access next to a step with no approval, an MCP server
pinned to a tag rather than a digest. Each is defensible alone. Together they
are the incident.

So this package models the graph and evaluates the combinations, and the
A-BOM it produces is the agent equivalent of the ML-BOM: a list a reader can
diff between two releases to see what gained a capability.
"""
from .capability import CAPABILITY_RULES, assess
from .declare import DeclarationError, load, load_text
from .model import (
    RELATIONS,
    Agent,
    AgentBom,
    DataSource,
    Effect,
    Identity,
    McpServer,
    Relation,
    SubAgent,
    Tool,
    diff,
)
from .vocabulary import VOCABULARY_VERSION, Access, Classification

__all__ = [
    "CAPABILITY_RULES",
    "RELATIONS",
    "VOCABULARY_VERSION",
    "Access",
    "Agent",
    "AgentBom",
    "DataSource",
    "DeclarationError",
    "Effect",
    "Identity",
    "Classification",
    "McpServer",
    "Relation",
    "SubAgent",
    "Tool",
    "assess",
    "diff",
    "load",
    "load_text",
]
