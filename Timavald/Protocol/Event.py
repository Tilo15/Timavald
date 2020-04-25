

class ProtocolEvent:

    EVENT_SEARCHING_FOR_PEERS = 0
    EVENT_ESTABLISHING_CONNECTION = 1
    EVENT_REQUESTING_FROM_PEER = 2
    EVENT_AWAITING_RESPONSE = 3
    EVENT_RECEIVING_RESPONSE = 4
    EVENT_RESPONDED = 5

    def __init__(self, event_type):
        self.type = event_type