from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk

# Load the public key
with open("./publickey.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

# Create JWK from public key
jwk_obj = jwk.JWK.from_pem(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))

# Convert JWK to dictionary
jwk_dict = jwk_obj.export(as_dict=True)

# Save JWK as JSON file
with open("jwk.json", "w") as jwk_file:
    jwk_file.write(jwk_obj.export())

print("JWK generated and saved as jwk.json")
