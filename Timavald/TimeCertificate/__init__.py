from Timavald.TimeSignature import TimeSignature
from Timavald.TrustSet import TrustSet

from typing import Iterable
from io import BytesIO
from nacl.signing import VerifyKey

import struct
import zlib
import hashlib

class TimeCertificate:

    def __init__(self, trust_set: TrustSet, trust_set_public_key: VerifyKey, time_signatures: Iterable[TimeSignature]):
        # Save the time signatures into a set
        self.signatures = set(time_signatures)

        # Create a trust set object
        self.trust_set = trust_set

        # Save the public key
        self.trust_set_key = trust_set_public_key


    def validate(self, message_hash):
        # Throw an error if there are not enough signatures
        if(len(self.signatures) < self.trust_set.required_signatures):
            raise ValueError("Time certificate contains less signatures than required by the trust set")

        # Keep a set of timestamps
        timestamps = set()

        # Loop over each signature
        for signature in self.signatures:
            # Do the hashes match?
            if(signature.hash != message_hash):
                raise Exception("Message hash does not match one or more of the signatures")

            # Is the signature in the TrustSet?
            if(signature.public_key.encode() not in self.trust_set.valid_key_data):
                raise Exception("A key was included in the certificate that is not in the trust set")

            # Add timestamp to the set
            timestamps.add(signature.time)

        # Find the max and min timestamp
        max_timestamp = max(timestamps)
        min_timestamp = min(timestamps)

        # Is the deviation within the certificate's tolerance?
        if(max_timestamp - min_timestamp > self.trust_set.maximum_deviation):
            raise Exception("Time deviation between signatures greater than acceptable by the trust set")

        # Are the times within the valid period of the trustset?
        if(max_timestamp > self.trust_set.valid_to and min_timestamp < self.trust_set.valid_from):
            raise Exception("Time signatures are outside of the period of validity of the trust set")

        # Return the timestamp
        return max_timestamp

    def validate_bytes(self, data: bytes):
        # Hash the data
        digest = hashlib.sha3_512(data).digest()

        # Sign the digest
        return self.validate(digest)

    
    def serialise(self):
        # Write the public key that signed the TrustSet
        data = self.trust_set_key.encode()

        # Write number of signatures
        data += struct.pack("!B", len(self.signatures))

        # Loop over each signature
        for signature in self.signatures:
            # Serialise the signature
            sig = signature.serialise()
            # Write the length of the signature
            data += struct.pack("!H", len(sig))
            # Write the signature
            data += sig

        # Add the trustset data
        data += self.trust_set.serialise()

        # Return serialised data
        return b"TVtimcrt" + zlib.compress(data, 9)

    
    @staticmethod
    def deserialise(certificate):
        # Is this a timecertificate?
        if(certificate[:8] != b"TVtimcrt"):
            raise ValueError("Supplied data is not a serialised TimeCertificate")

        # Decompress
        data = BytesIO(zlib.decompress(certificate[8:]))

        # Get the TrustSet public key
        public_key = VerifyKey(data.read(32))

        # Get number of signatures
        signature_count = struct.unpack("!B", data.read(1))[0]

        # Get all the signatures
        signatures = set()
        for i in range(signature_count):
            # Get the signature length
            signature_length = struct.unpack("!H", data.read(2))[0]

            # Get the signature
            signatures.add(TimeSignature.deserialise(data.read(signature_length)))

        # Get the trustset data
        trust_set = TrustSet.deserialise(data.read(), public_key)

        # Return the certificate
        return TimeCertificate(trust_set, public_key, signatures)
        





