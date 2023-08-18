import json
import requests
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from requests.structures import CaseInsensitiveDict
import uuid
import base64

def main():
    jti_value = str(uuid.uuid4())
    oauth_token_url = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token'
    message = {
        'iss': '6267b480-d0e8-445b-bc76-3691adc4ef04',
        'sub': '6267b480-d0e8-445b-bc76-3691adc4ef04',
        'aud': oauth_token_url,
        'jti': jti_value,
        'iat': int(datetime.now(timezone.utc).timestamp()),
        'exp': int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    }

    # Load JWK JSON file
    with open("jwk.json", "r") as jwk_file:
        jwk_data = json.load(jwk_file)

    # Get the kid value
    kid_value = jwk_data["kid"]

    # Construct JWT headers
    headers = {
        'alg': 'RS384',  # Use appropriate signing algorithm
        'typ': 'JWT',
        'kid': kid_value,  # Set to the kid of the target public key
    }

    # Load the private key
    with open("privatekey.pem", "rb") as key_file:
        private_key_pem = key_file.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    # Serialize headers and message to JSON strings
    encoded_headers = base64.urlsafe_b64encode(json.dumps(headers).encode()).rstrip(b'=')
    encoded_message = base64.urlsafe_b64encode(json.dumps(message).encode()).rstrip(b'=')

    # Concatenate header and payload
    data_to_sign = encoded_headers + b'.' + encoded_message

    # Sign the data
    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA384()
    )

    # Encode the signature and data
    encoded_signature = base64.urlsafe_b64encode(signature)
    
    # Construct the final JWT token
    encoded_data = data_to_sign + b'.' + encoded_signature
    
    headers = CaseInsensitiveDict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': encoded_data.decode().rstrip('=')  # Convert bytes to string
    }

    response = requests.request("POST", oauth_token_url, headers=headers, data=data)
    
    # Store the response JSON payload in a variable
    response_payload = response.json()
    print(response_payload)

if __name__ == "__main__":
    main()
