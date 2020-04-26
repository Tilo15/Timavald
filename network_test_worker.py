from Timavald import Network
from Timavald.Store.Disk import DiskStore
from Timavald.TrustSet import TrustSet
from Timavald.TimeSignature import TimeSignature

from nacl.signing import SigningKey
from nacl.signing import VerifyKey

store = DiskStore("store2")

# Generate 10 signing keys for the time signatures
signature_keys = [SigningKey.generate() for i in range(10)]

# Generate a signing key for the trust set
trust_set_private_key = SigningKey.generate()
trust_set_key = trust_set_private_key.verify_key

# Create a TrustSet valid from 1st of January 1970 until the 18th of May 2033 that requires at least 7 signatures within 120 seconds
trust_set = TrustSet.create("Useless Test", 0, 2000000000, (x.verify_key for x in signature_keys), 7, 120, trust_set_private_key)

for key in signature_keys:
    store.save_signing_key(key)

print("Saved: ", store.update_trust_set(trust_set_private_key.verify_key, trust_set))

network = Network(store)

print("Key: {}".format(trust_set_private_key.verify_key.encode().hex()))
# print(trust_set_private_key.verify_key.encode())
# kt = VerifyKey(bytes.fromhex(trust_set_private_key.verify_key.encode().hex()))
# tst = store.get_trust_set(kt)
# print("Self-test passed")
# print(tst.serialise())
# print(trust_set.serialise())