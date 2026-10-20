"""
Pipes & Filters Packet Processing Pipeline & Dead-Letter Capturer.
Rescued from 0.7/src/pkg/interfaces/pipeline.go.

Implements Single Responsibility Principle (SRP) per processing stage,
with deterministic stage chaining and dead-letter queueing for dropped/corrupted datagrams.
"""

from __future__ import annotations
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class PacketContext:
    raw_data: bytes
    remote_addr: str = "127.0.0.1:0"
    source_did: str = ""
    target_did: str = ""
    dropped: bool = False
    drop_reason: str = ""
    handled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def mark_dropped(self, reason: str):
        self.dropped = True
        self.drop_reason = reason

    def reset(self):
        self.raw_data = b""
        self.remote_addr = "127.0.0.1:0"
        self.source_did = ""
        self.target_did = ""
        self.dropped = False
        self.drop_reason = ""
        self.handled = False
        self.metadata.clear()
        self.timestamp = time.time()


class PipelineStage(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def process(self, p_ctx: PacketContext) -> bool:
        """
        Executes deterministic processing. Returns True to continue to next stage,
        or False to halt processing pipeline.
        """
        ...


class DeadLetterHandler(ABC):
    @abstractmethod
    def handle_dead_letter(self, p_ctx: PacketContext, stage_name: str, error: Optional[Exception] = None):
        ...


class InMemoryDeadLetterQueue(DeadLetterHandler):
    def __init__(self, max_capacity: int = 100):
        self.max_capacity = max_capacity
        self.dead_letters: List[Dict[str, Any]] = []

    def handle_dead_letter(self, p_ctx: PacketContext, stage_name: str, error: Optional[Exception] = None):
        entry = {
            "timestamp": time.time(),
            "stage": stage_name,
            "drop_reason": p_ctx.drop_reason,
            "source_did": p_ctx.source_did,
            "remote_addr": p_ctx.remote_addr,
            "raw_len": len(p_ctx.raw_data),
            "error": str(error) if error else None,
        }
        self.dead_letters.append(entry)
        if len(self.dead_letters) > self.max_capacity:
            self.dead_letters.pop(0)

    def get_summary(self) -> dict:
        return {
            "total_dead_letters": len(self.dead_letters),
            "recent": self.dead_letters[-5:],
        }


class DataPipeline:
    """
    Unidirectional sequential Pipes & Filters datagram processing pipeline.
    """

    def __init__(self, dead_letter_handler: Optional[DeadLetterHandler] = None):
        self._stages: List[PipelineStage] = []
        self._dead_letter_handler: DeadLetterHandler = dead_letter_handler or InMemoryDeadLetterQueue()
        self.stats = {
            "packets_processed": 0,
            "packets_dropped": 0,
            "packets_completed": 0,
        }

    def add_stage(self, stage: PipelineStage) -> DataPipeline:
        self._stages.append(stage)
        return self

    def set_dead_letter_handler(self, handler: DeadLetterHandler):
        self._dead_letter_handler = handler

    def execute(self, p_ctx: PacketContext) -> bool:
        """
        Executes sequential pipeline stages. Stops immediately if dropped or error occurs.
        """
        self.stats["packets_processed"] += 1

        for stage in self._stages:
            try:
                continue_pipeline = stage.process(p_ctx)
                if not continue_pipeline or p_ctx.dropped:
                    self.stats["packets_dropped"] += 1
                    self._dead_letter_handler.handle_dead_letter(p_ctx, stage.name)
                    return False
            except Exception as e:
                p_ctx.mark_dropped(f"Stage Exception ({stage.name}): {e}")
                self.stats["packets_dropped"] += 1
                self._dead_letter_handler.handle_dead_letter(p_ctx, stage.name, error=e)
                return False

        self.stats["packets_completed"] += 1
        p_ctx.handled = True
        return True

    def get_summary(self) -> dict:
        summary = {
            "stages": [s.name for s in self._stages],
            "stats": self.stats,
        }
        if isinstance(self._dead_letter_handler, InMemoryDeadLetterQueue):
            summary["dead_letter_queue"] = self._dead_letter_handler.get_summary()
        return summary
