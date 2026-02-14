__all__ = [
    "__version__",
    # Core
    "AgentIdentity",
    "AnchorManager",
    "AtlasManager",
    "HeartbeatManager",
    "AccordManager",
    "AgentMemory",
    # BEP-1: Proof-of-Thought
    "ThoughtProof",
    "ThoughtProofManager",
    # BEP-2: External Agent Relay
    "RelayAgent",
    "RelayManager",
    # BEP-4: Memory Markets
    "KnowledgeShard",
    "MemoryMarketManager",
    # BEP-5: Hybrid Districts
    "HybridDistrict",
    "HybridManager",
]

__version__ = "3.1.0"

# Lazy imports — only resolve when accessed.
from .identity import AgentIdentity  # noqa: E402, F401
from .anchor import AnchorManager  # noqa: E402, F401
from .atlas import AtlasManager  # noqa: E402, F401
from .heartbeat import HeartbeatManager  # noqa: E402, F401
from .accord import AccordManager  # noqa: E402, F401
from .memory import AgentMemory  # noqa: E402, F401
from .proof_of_thought import ThoughtProof, ThoughtProofManager  # noqa: E402, F401
from .relay import RelayAgent, RelayManager  # noqa: E402, F401
from .memory_market import KnowledgeShard, MemoryMarketManager  # noqa: E402, F401
from .hybrid_district import HybridDistrict, HybridManager  # noqa: E402, F401
