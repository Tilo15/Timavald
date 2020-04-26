from Timavald.TimeCertificate import TimeCertificate
from Timavald.TrustSet import TrustSet
from Timavald.TimeSignature import TimeSignature

from nacl.signing import VerifyKey
from threading import Timer
from rx.subject import Subject
from typing import Set

class TimeCertificateBuilder:

    def __init__(self, trust_set: TrustSet, trust_set_key: VerifyKey, digest: bytes, timeout: int = -1):
        # Save the paramaters
        self.trust_set = trust_set
        self.trust_set_key = trust_set_key
        self.timeout = timeout
        self.signatures: Set[TimeSignature] = set()
        self.result = Subject()
        self.digest = digest

        if(self.timeout == -1):
            self.timeout = trust_set.maximum_deviation

        self.__timer = None
        self.__complete = False

    def add_signature(self, signature: TimeSignature):
        # Do we have a timer?
        if(self.__timer == None):
            # No, create it
            self.__timer = Timer(self.timeout, self.__finalise)
            self.__timer.start()

        # Have we timed out?
        if(self.__complete):
            # Don't do anything
            return

        # Is the signature valid for this trust set?
        if(signature.public_key.encode() not in self.trust_set.valid_key_data):
            # Drop it
            return

        # Add to the signature set
        self.signatures.add(signature)

        # Have we got all the signatures?
        if(len(self.signatures) == len(self.trust_set.valid_keys)):
            # Yes, cancel timer and finalise
            self.__timer.cancel()
            self.__finalise()


    def __finalise(self):
        # We are complete
        self.__complete = True

        # Do we have enough signatures?
        if(len(self.signatures) < self.trust_set.required_signatures):
            # No, return error
            self.result.on_error(Exception("Could not get required number of signatures in time"))
            return

        # We have enough signatures for a certificate, build it
        certificate = TimeCertificate(self.trust_set, self.trust_set_key, self.signatures)

        # Verify the certificate
        try:
            certificate.validate(self.digest)
        except Exception as e:
            self.result.on_error(e)
            return

        # Send to the observer
        self.result.on_next(certificate)
        self.result.on_completed()