from Timavald import Network
from Timavald.Store.Disk import DiskStore
from Timavald.TrustSet import TrustSet
from Timavald.TimeSignature import TimeSignature

from nacl.signing import SigningKey
from nacl.signing import VerifyKey

import sys

store = DiskStore(sys.argv[1])
network = Network(store)