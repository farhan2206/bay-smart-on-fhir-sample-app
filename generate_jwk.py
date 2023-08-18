from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import json
import hashlib
import base64

# Load the X.509 public key
with open("public509.pem", "rb") as key_file:
    x509_cert_pem = key_file.read()

# Load the X.509 certificate
x509_cert = load_pem_x509_certificate(x509_cert_pem, default_backend())
public_key = x509_cert.public_key()

# Extract components of the public key
n = public_key.public_numbers().n
e = public_key.public_numbers().e

# Construct the JWK
jwk_dict = {
    "kty": "RSA",
    "n": n,
    "e": e,
    "kid": base64.urlsafe_b64encode(hashlib.sha256(n.to_bytes(256, 'big')).digest()).decode('utf-8')
}

# Save JWK as JSON file
with open("jwk.json", "w") as jwk_file:
    json.dump(jwk_dict, jwk_file, indent=4)

print("JWK generated and saved as jwk.json")
