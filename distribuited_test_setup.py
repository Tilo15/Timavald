from Timavald.Store.Disk import DiskStore
from Timavald.TrustSet import TrustSet
from Timavald.TimeSignature import TimeSignature

from nacl.signing import SigningKey
from nacl.signing import VerifyKey

import os

keys = set()

for i in range(5):
    os.mkdir("dstore{}".format(i))
    store = DiskStore("dstore{}".format(i))

    # Create the signing key
    signature_key = SigningKey.generate()
    store.save_signing_key(signature_key)
    keys.add(signature_key)

os.mkdir("dstore")
store = DiskStore("dstore")
# Generate a signing key for the trust set
trust_set_private_key = SigningKey.generate()
trust_set_key = trust_set_private_key.verify_key

# Create a TrustSet valid from 1st of January 1970 until the 18th of May 2033 that requires at least 7 signatures within 120 seconds
trust_set = TrustSet.create("Distribuited Test", 0, 2000000000, (x.verify_key for x in keys), 3, 120, trust_set_private_key)
store.update_trust_set(trust_set_key, trust_set)
    

print("Key: {}".format(trust_set_private_key.verify_key.encode().hex()))