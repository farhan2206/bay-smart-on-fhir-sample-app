import json
import requests

# Load JWKS keys from jwk.json file
with open("jwk.json", "r") as jwk_file:
    jwk_data = json.load(jwk_file)
    print(jwk_data)

# Define the endpoint URL and headers
url = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/register"
headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer Nxfve4q3H9TKs5F5vf6kRYAZqzK7j9LHvrg1Bw7fU_07_FdV9aRzLCI1GxOn20LuO2Ahl5RkRnz-p8u1MeYWqA85T8s4Ce3LcgQqIwsTkI7wezBsMduPw_xkVtLzLU2O",
}

# Define the payload for the POST request
payload = {
    "software_id": "d45049c3-3441-40ef-ab4d-b9cd86a17225",
    "jwks": {
        "keys": [jwk_data]  # Use the loaded JWKS keys
    }
}

# Make the POST request
response = requests.post(url, headers=headers, json=payload)

# Print the response content
print("----------------RESPONSE----------")
print(response.text)
