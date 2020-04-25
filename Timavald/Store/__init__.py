from Timavald.TrustSet import TrustSet
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from typing import List

class Store:

    def get_trust_set(self, public_key: VerifyKey) -> TrustSet:
        raise NotImplementedError()

    def update_trust_set(self, public_key: VerifyKey, trust_set: TrustSet) -> bool:
        raise NotImplementedError()

    def get_signing_key(self, public_key: VerifyKey) -> SigningKey:
        raise NotImplementedError()

    def save_signing_key(self, signing_key: SigningKey):
        raise NotImplementedError()

    def has_trust_set(self, public_key: VerifyKey) -> bool:
        raise NotImplementedError()

    def has_signing_key(self, public_key: VerifyKey) -> bool:
        raise NotImplementedError()

    def get_resources(self) -> List[bytes]:
        raise NotImplementedError()