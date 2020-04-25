from Timavald.Protocol.Event import ProtocolEvent
from typing import TypeVar, Generic

T = TypeVar('T')

class ProtocolResult(ProtocolEvent, Generic[T]):

    def __init__(self, result: T):
        self.result = result
        self.type = ProtocolEvent.EVENT_RESPONDED