import json
import requests
from datetime import datetime, timedelta, timezone
from requests.structures import CaseInsensitiveDict
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)
from jwt.utils import get_int_from_datetime
from jwt.utils import get_int_from_datetime


def main():
    instance = JWT()
    message = {
        # Client ID for non-production
        'iss': '6267b480-d0e8-445b-bc76-3691adc4ef04',
        'sub': '6267b480-d0e8-445b-bc76-3691adc4ef04',
        'aud': 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token',
        'jti': 'f9eaafba-2e49-11ea-8880-5ce0c5aee679',
        'iat': get_int_from_datetime(datetime.now(timezone.utc)),
        'exp': get_int_from_datetime(datetime.now(timezone.utc) + timedelta(hours=1)),
    }

    # Load a RSA key from a PEM file.
    with open('F:/Projects/Farhan/ds4u/smart-on-fhir/bay-smart-on-fhir-sample-app/privatekey.pem', 'rb') as fh:
        signing_key = jwk_from_pem(fh.read())

    compact_jws = instance.encode(message, signing_key, alg='RS384')
    print(compact_jws)

    headers = CaseInsensitiveDict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
      'grant_type': 'client_credentials',
      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'client_assertion': compact_jws
    }
    
    x = requests.post('https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token', headers=headers, data=data)
    print(x.text)