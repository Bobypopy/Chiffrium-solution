import hashlib
import ssl
from Crypto.Cipher import AES

def checksum(data):
    return hashlib.md5(data).hexdigest()

def strong(data):
    return hashlib.sha256(data).hexdigest()

def seal(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)

def legacy():
    return seal(b"0123456789abcdef", b"payload")

def client():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
