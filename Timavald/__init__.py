from Timavald.Protocol import Protocol
from Timavald.Protocol.Event import ProtocolEvent
from Timavald.Protocol.Result import ProtocolResult
from Timavald.Store import Store
from Timavald.TrustSet import TrustSet
from Timavald.TimeCertificate.Builder import TimeCertificateBuilder

from nacl.signing import VerifyKey
from rx.subject import Subject
from threading import Timer

import hashlib

class Network:

    def __init__(self, store: Store):
        self.store = store
        self.protocol = Protocol(store)
    

    def sign_digest(self, digest: bytes, trust_set_key: bytes):
        # Create the subject
        subject = Subject()

        # Create a VerifyKey from the bytes
        key = VerifyKey(trust_set_key)

        # Handle trust set
        def on_trust_set(trust_set: TrustSet):
            # Create a TimeCertificateBuilder to handle this request
            builder = TimeCertificateBuilder(trust_set, trust_set_key)

            # Hook up the result to our subject
            builder.result.subscribe(subject.on_next, subject.on_error, subject.on_completed)

            # Prepare to handle signature request events
            def handle_sig_events(event: ProtocolEvent):
                if(event.type == ProtocolEvent.EVENT_RESPONDED):
                    builder.add_signature(event.result)

                else:
                    self.__print_event(event)

            # Iterate over the valid public keys
            for key in trust_set.valid_keys:
                # Request a signature
                self.protocol.request_signature(key, digest).subscribe(handle_sig_events)


        def handle_tsr_events(event: ProtocolEvent):
            if(event.type == ProtocolEvent.EVENT_RESPONDED):
                on_trust_set(event.result)

            else:
                self.__print_event(event)

        # Do we have the trust set?
        if(self.store.has_trust_set(key)):
            print("Trust set found locally")
            on_trust_set(self.store.get_trust_set(key))
        
        else:
            self.protocol.request_trust_set(key).subscribe(handle_tsr_events)

        return subject


    def sign_bytes(self, data: bytes, trust_set_key: bytes):
        # Hash the data
        digest = hashlib.sha3_512(data).digest()

        # Sign the digest
        return self.sign_digest(digest, trust_set_key)
    

    __event_messages = {
        ProtocolEvent.EVENT_ESTABLISHING_CONNECTION: "Establishing stream to remote peer",
        ProtocolEvent.EVENT_SEARCHING_FOR_PEERS: "Looking for matching peers",
        ProtocolEvent.EVENT_REQUESTING_FROM_PEER: "Sending request to peer",
        ProtocolEvent.EVENT_AWAITING_RESPONSE: "Waiting for peer to respond",
        ProtocolEvent.EVENT_RECEIVING_RESPONSE: "Receiving response from peer",
    }
    
    def __print_event(self, event: ProtocolEvent):
        print(self.__event_messages[event.type])
