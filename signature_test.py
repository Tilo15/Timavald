from Timavald.TrustSet import TrustSet
from Timavald.TimeSignature import TimeSignature
from Timavald.TimeCertificate import TimeCertificate

from nacl.signing import SigningKey
from datetime import datetime

import hashlib

# Generate 10 signing keys for the time signatures
signature_keys = [SigningKey.generate() for i in range(10)]

# Generate a signing key for the trust set
trust_set_private_key = SigningKey.generate()
trust_set_key = trust_set_private_key.verify_key

# Create a TrustSet valid from 1st of January 1970 until the 18th of May 2033 that requires at least 7 signatures within 120 seconds
trust_set = TrustSet.create("Useless Test", 0, 2000000000, (x.verify_key for x in signature_keys), 7, 120, trust_set_private_key)

# Make a message
message = "Super important time sensitive message"

# Hash the message
message_hash = hashlib.sha3_512(message.encode("UTF-8")).digest()

# "Send" to all the trusted signers
signatures = [TimeSignature.sign(message_hash, k) for k in signature_keys]

# Create a time certifcate from the signatures
certificate_data = TimeCertificate(trust_set, trust_set_key, signatures).serialise()

## VERIFY ##

# Get the certificate
certificate = TimeCertificate.deserialise(certificate_data)

# Generate the message hash
message_hash = hashlib.sha3_512(message.encode("UTF-8")).digest()

# Validate the hash against the certificate
timestamp = certificate.validate(message_hash)

print("Message was signed at {} UTC and was signed using the '{}' trust set,".format(datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'), certificate.trust_set.name))
print("certificate was {} bytes.".format(len(certificate.serialise())))