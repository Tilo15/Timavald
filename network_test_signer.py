from Timavald.Store.Disk import DiskStore
from Timavald import Network

from datetime import datetime
import time


store = DiskStore("store")
network = Network(store)

key = bytes.fromhex(input("Key > "))
print(key)

start_time = int(time.time())

message = b"My super important and time sensitive message"

# Success callback
def complete(certificate):
    timestamp = certificate.validate_bytes(message)
    print()
    print()
    print("Message was signed at {} UTC and was signed using the '{}' trust set.".format(datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'), certificate.trust_set.name))
    print("Certificate was {} bytes.".format(len(certificate.serialise())))
    print("Start time was {} UTC.".format(datetime.utcfromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')))


def error(exception):
    raise exception

print("Signing")
network.sign_bytes(message, key).subscribe(complete, error)