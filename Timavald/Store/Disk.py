from Timavald.Store import Store
from Timavald.TrustSet import TrustSet

from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from nacl.encoding import Base32Encoder
from typing import Iterable

import os
import base64

class DiskStore(Store):

    def __init__(self, location):
        self.location = location


    def get_trust_set(self, public_key: VerifyKey) -> TrustSet:
        # Read the trust set file
        file = open(os.path.join(self.location, public_key.encode(Base32Encoder).decode("utf-8")), 'rb')
        data = file.read()
        file.close()

        # Construct and return the trust set
        return TrustSet.deserialise(data, public_key)


    def update_trust_set(self, public_key: VerifyKey, trust_set: TrustSet) -> bool:
        # Does the path already exist?
        if(self.has_trust_set(public_key)):
            # Get the trust set
            current = self.get_trust_set(public_key)

            # If the current trust set is valid from a later date, don't update
            if(trust_set.valid_from < current.valid_from):
                return False

        # Replace/create the trust set
        file = open(os.path.join(self.location, public_key.encode(Base32Encoder).decode("utf-8")), 'wb')
        file.write(trust_set.serialise())
        file.close()
        return True


    def get_signing_key(self, public_key: VerifyKey) -> SigningKey:
        # Read the key file
        file = open(os.path.join(self.location, public_key.encode(Base32Encoder).decode("utf-8")), 'rb')
        data = file.read()
        file.close()

        # Construct and return the signing key
        return SigningKey(data)


    def save_signing_key(self, signing_key: SigningKey):
        # Save the signing key
        file = open(os.path.join(self.location, signing_key.verify_key.encode(Base32Encoder).decode("utf-8")), 'wb')
        file.write(signing_key.encode())
        file.close()


    def has_trust_set(self, public_key: VerifyKey) -> bool:
        return os.path.exists(os.path.join(self.location, public_key.encode(Base32Encoder).decode("utf-8")))


    def has_signing_key(self, public_key: VerifyKey) -> bool:
        return os.path.exists(os.path.join(self.location, public_key.encode(Base32Encoder).decode("utf-8")))


    def get_resources(self) -> Iterable[bytes]:
        res = os.listdir(self.location)
        for file in res:
            yield base64.b32decode(file)