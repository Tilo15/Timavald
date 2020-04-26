from typing import Iterable
from nacl.signing import VerifyKey
from nacl.signing import SigningKey
from io import BytesIO

import struct

class TrustSet:

    def __init__(self, name: str, valid_from: int, valid_to: int, valid_keys: Iterable[VerifyKey], required_signatures: int, maximum_deviation: int, signature):
        # Save properties
        self.name = name
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.valid_keys = set(valid_keys)
        self.valid_key_data = set(k.encode() for k in self.valid_keys)
        self.required_signatures = required_signatures
        self.maximum_deviation = maximum_deviation
        self.signature = signature


    @staticmethod
    def create(name: str, valid_from: int, valid_to: int, valid_keys: Iterable[VerifyKey], required_signatures: int, maximum_deviation: int, signing_key: SigningKey):
        # Convert iterable keys to set
        keys = set(valid_keys)

        # Create the data to sign
        data = struct.pack("!QQHBB", valid_from, valid_to, maximum_deviation, required_signatures, len(keys))

        # Add the keys
        for key in keys:
            data += key.encode()
        
        # Add the name
        data += name.encode("UTF-8")

        # Sign the trust set
        signed = signing_key.sign(data)

        # Return the object
        return TrustSet(name, valid_from, valid_to, keys, required_signatures, maximum_deviation, signed)

    
    def serialise(self) -> bytes:
        # Return the trust set
        return b"TVtrstst" + self.signature

    
    @staticmethod
    def deserialise(data: bytes, public_key: VerifyKey):
        # Is this a trustset?
        if(data[:8] != b"TVtrstst"):
            raise ValueError("Supplied data is not a serialised TrustSet")

        # Verify the data
        signature = public_key.verify(data[8:])
        buffer = BytesIO(signature)

        # Read the header
        valid_from, valid_to, maximum_deviation, required_signatures, key_count = struct.unpack("!QQHBB", buffer.read(20))


        # Read the keys
        keys = set()
        for i in range(key_count):
            keys.add(VerifyKey(buffer.read(32)))
        
        # Read the trust set display name
        name = buffer.read().decode("UTF-8")

        # Create the trust set
        return TrustSet(name, valid_from, valid_to, keys, required_signatures, maximum_deviation, data[8:])

        
