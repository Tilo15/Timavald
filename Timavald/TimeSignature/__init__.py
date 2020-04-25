from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from io import BytesIO

import struct
import time

class TimeSignature:

    def __init__(self, message_hash: bytes, time_signed: int, public_key: VerifyKey, signature: bytes):
        self.hash = message_hash
        self.time = time_signed
        self.public_key = public_key
        self.signature = signature


    def serialise(self):
        return b"TVtimsig" + self.public_key.encode() + self.signature
    

    @staticmethod
    def sign(message_hash: bytes, key: SigningKey):
        # Make sure the hash is of valid length
        if(len(message_hash) != 64):
            raise TypeError("Message hash must be SHA512 but data provided is not 64 bytes long")

        # Create the data
        data = message_hash

        # Get the time for the timestamp
        timestamp = int(time.time())

        # Add the time
        data += struct.pack("!Q", timestamp)

        # Sign the data
        signed = key.sign(data)

        # Return the signature
        return TimeSignature(message_hash, timestamp, key.verify_key, signed)


    @staticmethod
    def deserialise(serialised: bytes):
        # Is this a timesignature?
        if(serialised[:8] != b"TVtimsig"):
            raise ValueError("Supplied data is not a serialised TimeSignature")

        # Read the public key
        public_key = VerifyKey(serialised[8:40])

        # Read the signature
        signature = serialised[40:]

        # Verify data
        data = BytesIO(public_key.verify(signature))

        # Get the message hash
        message_hash = data.read(64)

        # Get the timestamp
        timestamp = struct.unpack("!Q", data.read(8))[0]

        # Return the object
        return TimeSignature(message_hash, timestamp, public_key, signature)


        