import hashlib
import base64

def hash(input_string):
    sha256_hash = hashlib.sha256(input_string.encode()).digest()

    return base64.b64encode(sha256_hash).decode()

def hash_hex(input_string):
    sha256_hash = hashlib.sha256(input_string.encode()).hexdigest()

    return sha256_hash


password = "Intrustion"
hash1=hash_hex(password)
print(hash1)
print(f"Length of the hash is {len(hash1)} and the hash is {hash1}") 