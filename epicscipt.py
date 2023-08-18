import json
import requests
from datetime import datetime, timedelta, timezone
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from requests.structures import CaseInsensitiveDict
import uuid

def main():
    jti_value = str(uuid.uuid4())
    message = {
        'iss': '96843565-cce9-4d38-b3f5-4ed8624b1795',
        'sub': '96843565-cce9-4d38-b3f5-4ed8624b1795',
        'aud': 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token',
        'jti': jti_value,
        'iat': int(datetime.now(timezone.utc).timestamp()),
        'exp': int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    }

    # Load JWK JSON file
    with open("jwk.json", "r") as jwk_file:
        jwk_data = json.load(jwk_file)

    # Get the kid value
    kid_value = jwk_data["kid"]
    print("Key ID (kid) value:", kid_value)

    # Construct JWT headers
    headers = {
        'alg': 'RS384',  # Use appropriate signing algorithm
        'typ': 'JWT',
        'kid': kid_value,  # Set to the kid of the target public key
    }

    print(headers)

    # Load the private key
    with open("privatekey.pem", "rb") as key_file:
        private_key_pem = key_file.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    compact_jws = jwt.encode(message, private_key, algorithm='RS384', headers=headers)
    print(compact_jws)

    headers = CaseInsensitiveDict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': compact_jws
    }
    print(data)
    print(headers)
    response = requests.post('https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token', headers=headers, data=data)
    print(response)
    print(response.text)

if __name__ == "__main__":
    main()
