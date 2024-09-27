import json
import requests
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from requests.structures import CaseInsensitiveDict
import uuid
import base64
from datetime import datetime


def get_access_token():
    jti_value = str(uuid.uuid4())
    oauth_token_url = 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token'
    message = {
        'iss': '8274ef80-78f0-43b5-b433-55aebb061c12',
        'sub': '8274ef80-78f0-43b5-b433-55aebb061c12',
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
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=')
    
    # Construct the final JWT token
    encoded_data = data_to_sign + b'.' + encoded_signature
    
    headers = CaseInsensitiveDict()
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    data = {
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': encoded_data.decode()  # Convert bytes to string
    }

    response = requests.post(oauth_token_url, headers=headers, data=data)
    
    if response.status_code == 200:
        response_payload = response.json()
        print(response_payload)
        return response_payload.get("access_token")
    else:
        print(f"Failed to obtain access token: {response.status_code}")
        print(response.text)
        return None
    
    
def fetch_patient_data(access_token):
    patient_api_url = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Patient/erXuFYUfucBZaryVksYEcMg3' #FHIRCAMILA PATIENT FROM TESTING SANDBOX ENV
    headers = CaseInsensitiveDict()
    headers['Authorization'] = f'Bearer {access_token}'
    headers['Accept'] = 'application/json'

    response = requests.get(patient_api_url, headers=headers)
    if response.status_code == 200:
        patient_data = response.json()
        return patient_data
    else:
        print(f"Failed to fetch patient data: {response.status_code}")
        print(response.text)
        return None
    
def fetch_patient_appointment(access_token):
    appointment_patient_api_url = 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Appointment?patient=erXuFYUfucBZaryVksYEcMg3&service-category=appointment' #FHIRCAMILA PATIENT APPOINTMENT FROM TESTING SANDBOX ENV
    headers = CaseInsensitiveDict()
    headers['Authorization'] = f'Bearer {access_token}'
    headers['Accept'] = 'application/json'

    response = requests.get(appointment_patient_api_url, headers=headers)
    if response.status_code == 200:
        appointment_data = response.json()
        return appointment_data
    else:
        print(f"Failed to fetch patient data: {response.status_code}")
        print(response.text)
        return None
        
def checkAppointments(access_token): 
    appointment_find_url = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Appointment/$find"
    headers = CaseInsensitiveDict()
    headers['Authorization'] = f'Bearer {access_token}'
    headers['Content-Type'] = 'application/json'
    headers['Accept'] = 'application/json'

    data = {"resourceType":"Parameters","parameter":[{"name":"patient","resource":{"resourceType":"Patient","extension":[{"valueCode":"M","url":"http://hl7.org/fhir/us/core/StructureDefinition/us-core-birthsex"},{"extension":[{"valueCoding":{"system":"http://hl7.org/fhir/us/core/ValueSet/omb-race-category","code":"2106-3","display":"White"},"url":"ombCategory"},{"valueString":"White","url":"text"}],"url":"http://hl7.org/fhir/us/core/StructureDefinition/us-core-race"},{"extension":[{"valueCoding":{"system":"http://hl7.org/fhir/us/core/ValueSet/omb-ethnicity-category","code":"UNK","display":"Unknown"},"url":"ombCategory"},{"valueString":"Unknown","url":"text"}],"url":"http://hl7.org/fhir/us/core/StructureDefinition/us-core-ethnicity"}],"identifier":[{"use":"usual","type":{"text":"EPIC"},"system":"urn:oid:1.2.840.114350.1.1","value":"E3423"},{"use":"usual","type":{"text":"MRN"},"system":"urn:oid:1.2.840.114350.1.13.0.1.7.5.737384.14","value":"203177"}],"active":"true","name":[{"use":"usual","text":"Correct Professional Billing","family":"Professional Billing","given":["Correct"]}],"telecom":[{"system":"phone","value":"608-271-9000","use":"home"},{"system":"phone","value":"608-271-9000","use":"work"}],"gender":"male","birthDate":"1983-06-08","address":[{"use":"home","line":["1979 Milky Way"],"city":"VERONA","district":"DANE","state":"WI","postalCode":"53593","country":"US"}],"maritalStatus":{"text":"Single"},"communication":[{"language":{"coding":[{"system":"http://hl7.org/fhir/ValueSet/languages","code":"en","display":"English"}],"text":"English"},"preferred":"true"}],"generalPractitioner":[{"reference":"https://apporchard.epic.com/interconnect-aocurprd-oauth/api/FHIR/STU3/Practitioner/eM5CWtq15N0WJeuCet5bJlQ3","display":"Physician Family Medicine, MD"}],"managingOrganization":{"reference":"https://apporchard.epic.com/interconnect-aocurprd-oauth/api/FHIR/STU3/Organization/enRyWnSP963FYDpoks4NHOA3","display":"Epic Hospital System"}}},{"name":"startTime","valueDateTime":"2024-05-01T13:00:00Z"},{"name":"endTime","valueDateTime":"2028-05-05T22:00:00Z"},{"name":"serviceType","valueCodeableConcept":{"coding":[{"system":"urn:oid:1.2.840.114350.1.13.0.1.7.3.808267.11","code":"95014","display":"Office Visit"}]}},{"name":"indications","valueCodeableConcept":{"coding":[{"system":"urn:oid:2.16.840.1.113883.6.96","code":"46866001","display":"Fracture of lower limb (disorder)"},{"system":"urn:oid:2.16.840.1.113883.6.90","code":"S82.90XA","display":"Broken leg"},{"system":"urn:oid:1.2.840.114350.1.13.861.1.7.2.696871","code":"121346631","display":"Broken leg"}],"text":"Broken leg"}},{"name":"location-reference","valueReference":{"reference":"https://apporchard.epic.com/interconnect-aocurprd-oauth/api/FHIR/STU3/Location/e4W4rmGe9QzuGm2Dy4NBqVc0KDe6yGld6HW95UuN-Qd03"}}]}

    # Send the POST request
    response = requests.post(url=appointment_find_url, headers=headers, data=json.dumps(data))

    # Check if the request was successful
    if response.status_code == 200:
        print("Request was successful!")
        return response.json()
    else:
        print(f"Request failed with status code {response.status_code}")
        print("Response:", response.text)
        return None
    
def find_appointments(access_token, start_date, end_date):
    # Convert strings to datetime objects if necessary
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
    if isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d')

    # Format dates to FHIR-compatible format (YYYY-MM-DD)
    start_date_str = start_date.strftime('%Y-%m-%d')
    end_date_str = end_date.strftime('%Y-%m-%d')

    # Construct the FHIR search URL
    appointment_patient_api_url = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Appointment"
    
    # Define the search parameters
    params = {
        'patient': 'erXuFYUfucBZaryVksYEcMg3',
        'date': f"{start_date_str}|{end_date_str}"
    }
    
    try:
        # Make the GET request to the FHIR server
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        response = requests.get(appointment_patient_api_url, headers=headers, params=params)
        if response.status_code == 200:
            appointment_data = response.json()
            return appointment_data
        else:
            print(f"Failed to fetch patient data: {response.status_code}")
            print(response.text)
            return None
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return []

def create_appointment(access_token, appointment_data):
    # Construct the FHIR URL for creating an Appointment
    create_appointment_url = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Appointment/$book"
    # Set the headers for the request
    headers = CaseInsensitiveDict()
    headers['Authorization'] = f'Bearer {access_token}'
    headers['Content-Type'] = 'application/fhir+json'
    headers['Accept'] = 'application/json'

    try:
        # Send the POST request
        response = requests.post(url=create_appointment_url, headers=headers, json=appointment_data)
        if response.status_code in [200, 201]:  # Check for success (200 OK or 201 Created)
            appointment_created_data = response.json()
            return appointment_created_data
        else:
            print(f"Failed to create appointment: {response.status_code}")
            print(response.text)
            return None
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return []


def main():
    access_token = get_access_token()
    if access_token:
        patient_data = fetch_patient_data(access_token)
        if patient_data:
            print(json.dumps(patient_data, indent=2))
        
        print("#####################################################################################################################################################")
            
        # appointment_data = fetch_patient_appointment(access_token)
        # if appointment_data:
        #     print(json.dumps(appointment_data, indent=2))
        # start_date = datetime(2024, 9, 27)
        # end_date = datetime(2024, 9, 27)
        # appointment_data = find_appointments(access_token, start_date, end_date)
        appointment_data = checkAppointments(access_token)
        if appointment_data:
            print(json.dumps(appointment_data, indent=2))
        
        print("#####################################################################################################################################################")
        
        appointment_data = {
        "resourceType": "Parameters",
        "parameter": [
            {
            "name": "patient",
            "valueIdentifier": {
                "value": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/STU3/Patient/ev4L1e2V1ZwRwejbW-AxlHQ3"
            }
            },
            {
            "name": "appointment",
            "valueIdentifier": {
                "value": "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/Appointment/enALxdm6GUiZGPFjWlTfGYepp5iqTDMV6KKvcg9ATaMJTKA3u5KsVeSYjQ.E0TafK3"
            }
            },
            {
            "name": "appointmentNote",
            "valueString": "Note text containing info related to the appointment."
            }
        ]
        }

        
        appointment_created_data = create_appointment(access_token, appointment_data)
        if appointment_created_data:
            print(json.dumps(appointment_data, indent=2))

if __name__ == "__main__":
    main()