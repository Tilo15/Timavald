from Timavald.Store import Store
from Timavald.TimeSignature import TimeSignature
from Timavald.TrustSet import TrustSet
from Timavald.Protocol.Event import ProtocolEvent
from Timavald.Protocol.Result import ProtocolResult

from LibPeer2 import InstanceManager
from LibPeer2.Protocols.STP.Stream.IngressStream import IngressStream
from LibPeer2.Protocols.STP.Stream.EgressStream import EgressStream
from nacl.signing import VerifyKey
from nacl.signing import SigningKey

import rx.subject
import struct

class Protocol:

    REQUEST_TRUST_SET = b"TRST"
    REQUEST_TRUST_SET_UPDATE = b"PUSH"
    REQUEST_SIGNATURE = b"SIGN"


    def __init__(self, store: Store):
        # Keep reference to store
        self.store = store

        # Create the instance
        self.instance = InstanceManager("org.unitatem.timavald")

        # Hook up request handler
        self.instance.new_stream.subscribe(self.handle_request)

        # Add signatures as LibPeer resoureces
        for resource in self.store.get_resources():
            self.instance.resources.add(resource)

    
    def handle_request(self, stream: IngressStream):
        # New connection, see what they want
        command = stream.read(4)

        if(command == Protocol.REQUEST_TRUST_SET):
            # Trust set requested, get the public key
            public_key = VerifyKey(strem.read(32))

            # Certificate requested, do we have it?
            if(self.store.has_trust_set(public_key)):
                # Yes, get ready to reply
                def established(egress: EgressStream):
                    # Get the trust set
                    trust_set = self.store.get_trust_set(public_key)

                    # Send the trust set
                    self.send_response(trust_set.serialise(), egress)

                # Reply to the request
                self.instance.establish_stream(stream.origin, stream.id).subscribe(established)

        elif(command == Protocol.REQUEST_SIGNATURE):
            # Signature requested, get the public key
            public_key = VerifyKey(strem.read(32))
            
            # Get the message hash
            digest = stream.read(64)

            # Do we have the private key for this public key?
            if(self.store.has_signing_key(public_key)):
                # Yes, get ready to reply
                def established(egress: EgressStream):
                    # Get the signing key
                    signing_key = self.store.get_signing_key(public_key)

                    # Create the time signature
                    signature = TimeSignature.sign(digest, signing_key)

                    # Send the signature
                    self.send_response(signature.serialise(), egress)

                # Reply to the request
                self.instance.establish_stream(stream.origin, stream.id).subscribe(established)

                    
    def send_response(self, data: bytes, stream: EgressStream):
        size = len(data)
        stream.write(b"OK" + struct.pack("!I", size) + data)
        stream.close()

    def read_response(self, stream: IngressStream):
        if(strem.read(2) != "OK"):
            raise IOError("Peer returned bad response")

        size = struct.unpack("!I", stream.read(4))[0]
        data = stream.read(size)
        stream.close()
        return data


    def request_trust_set(self, key: VerifyKey):
        # Create a subject for the request
        subject = rx.subject.ReplaySubject()
        
        # Looking for peers
        subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_SEARCHING_FOR_PEERS))

        # Prepare for response from peer
        def peer_responded(stream: IngressStream):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_RECEIVING_RESPONSE))

            # Read the trust set
            trust_set = TrustSet.deserialise(self.read_response(stream), key)

            # Update our local copy of it
            self.store.update_trust_set(trust_set)

            # Return the response
            subject.on_next(ProtocolResult(trust_set))

        # Prepare to connet to peer
        def peer_connected(stream: EgressStream):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_REQUESTING_FROM_PEER))

            # Subscribe to the reply
            stream.reply.subscribe(peer_responded)

            # Make the request
            stream.write(Protocol.REQUEST_TRUST_SET + key.encode())
            stream.close()

            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_AWAITING_RESPONSE))

        # Prepare to find peers
        def peer_found(peer):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_ESTABLISHING_CONNECTION))

            # Establish connection
            self.instance.establish_stream(peer).on_next(peer_connected)


        # Find peers with the trust set
        self.instance.find_resource_peers(key.encode()).subscribe(peer_found)

        # Return the subject
        return subject


    def request_signature(self, key: VerifyKey, digest: bytes):
        # Check digest is valid
        if(len(digest) != 64):
            raise ValueError("Digest must be a SHA512 hash")

        # Create a subject for the request
        subject = rx.subject.ReplaySubject()
        
        # Looking for peers
        subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_SEARCHING_FOR_PEERS))

        # Prepare for response from peer
        def peer_responded(stream: IngressStream):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_RECEIVING_RESPONSE))

            # Read the time signature
            time_signature = TimeSignature.deserialise(self.read_response(stream))

            # Return the response
            subject.on_next(ProtocolResult(time_signature))
            subject.on_completed()

        # Prepare to connet to peer
        def peer_connected(stream: EgressStream):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_REQUESTING_FROM_PEER))

            # Subscribe to the reply
            stream.reply.subscribe(peer_responded)

            # Make the request
            stream.write(Protocol.REQUEST_SIGNATURE + key.encode() + digest)
            stream.close()

            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_AWAITING_RESPONSE))

        # Prepare to find peers
        def peer_found(peer):
            # Notify subject
            subject.on_next(ProtocolEvent(ProtocolEvent.EVENT_ESTABLISHING_CONNECTION))

            # Establish connection
            self.instance.establish_stream(peer).on_next(peer_connected)


        # Find peer with the signing key
        self.instance.find_resource_peers(key.encode()).subscribe(peer_found)

        # Return the subject
        return subject

        
        


        
        