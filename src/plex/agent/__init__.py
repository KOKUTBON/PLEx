"""PLEx autonomous agent layer providing optional model-driven investigation under scope controls."""

from .commands import add_agent_commands, cmd_agent
from .coordinator import (
    MultiWorkerCoordinator,
    SpecialistRole,
    TeamState,
    WorkerReport,
    WorkerTask,
)
from .models import (
    AgentRole,
    AgentScopePolicy,
    AgentState,
    AgentStatus,
    AgentStep,
    ScopeViolationError,
    ToolCall,
    ToolResult,
)
from .provider import (
    LocalMockModelProvider,
    ModelMessage,
    ModelProvider,
    ModelResponse,
    OllamaModelProvider,
    OpenAICompatibleProvider,
    get_model_provider,
)
from .tools import ToolContext, ToolRegistry
from .worker import SingleWorkerAgent

__all__ = [
    "AgentRole",
    "AgentScopePolicy",
    "AgentState",
    "AgentStatus",
    "AgentStep",
    "LocalMockModelProvider",
    "ModelMessage",
    "ModelProvider",
    "ModelResponse",
    "MultiWorkerCoordinator",
    "OllamaModelProvider",
    "OpenAICompatibleProvider",
    "ScopeViolationError",
    "SingleWorkerAgent",
    "SpecialistRole",
    "TeamState",
    "ToolCall",
    "ToolContext",
    "ToolRegistry",
    "ToolResult",
    "WorkerReport",
    "WorkerTask",
    "add_agent_commands",
    "cmd_agent",
    "get_model_provider",
]
