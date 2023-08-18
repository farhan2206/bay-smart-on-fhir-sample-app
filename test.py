import gradio as gr
import openai, config
from fastapi import FastAPI
import os
import asyncio
import json
import requests
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from requests.structures import CaseInsensitiveDict
import uuid
import base64

openai.api_key = config.OPENAI_API_KEY

app = FastAPI()

def perform_epic_fhir_call():
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
    return response_payload
    


@app.get("/")
async def transcribe(audio=None, text=None):
    # Call the function to perform the Epic FHIR call and get the response payload
    print('-----START THE EPIC FHIR CALL-------------------')
    epic_fhir_response = perform_epic_fhir_call()
    print('-----END THE EPIC FHIR CALL---------------------')
    print("current working directory:", os.getcwd())
    print("audio parameter value:", audio) # added line
    if audio is not None:
        # Perform transcription on the audio file
        messages = [{"role": "system", "content": 'You are a kind nurse and transcriber named Alicja'}]
    
        from pydub import AudioSegment
        
        print("audio parameter value:", audio)
        audio_file_wav = open(os.path.join(os.getcwd(), audio), "rb")
        audio_file_mp3 = AudioSegment.from_wav(audio_file_wav).export("audio.mp3", format="mp3")
        transcript = openai.Audio.transcribe("whisper-1", audio_file_mp3)
    
        messages.append({"role": "user", "content": transcript["text"]})
    
        response = await asyncio.to_thread(openai.ChatCompletion.create, model="gpt-3.5-turbo", messages=messages)
    
        system_message = response["choices"][0]["message"]
        messages.append(system_message)
    
        chat_transcript = ""
        for message in messages:
            if message['role'] != 'system':
                chat_transcript += message['role'] + ": " + message['content'] + " "
    
        chat_transcript = chat_transcript.replace('\n\n', ' ')
    
        return {
            "chat_transcript": chat_transcript,
            "epic_fhir_response": epic_fhir_response
        }
    
    
    elif text is not None:
        # Perform transcription on the text input
        messages = [{"role": "system", "content": 'You are a kind nurse and transcriber named Alicja'},
                    {"role": "user", "content": text}]
    
        response = await asyncio.to_thread(openai.ChatCompletion.create, model="gpt-3.5-turbo", messages=messages)
    
        system_message = response["choices"][0]["message"]
        messages.append(system_message)
    
        chat_transcript = ""
        for message in messages:
            if message['role'] != 'system':
                chat_transcript += message['role'] + ": " + message['content'] + " "
    
        chat_transcript = chat_transcript.replace('\n\n', ' ')
    
        return {
            "chat_transcript": chat_transcript,
            "epic_fhir_response": epic_fhir_response
        }
ui = gr.Interface(
    fn=transcribe, 
    theme='gradio/base',
    inputs=[
        gr.Audio(source="microphone", type="filepath", label="Upload audio"),
        gr.Textbox(label="Or chat here:"),
        
    ],
    outputs=gr.Textbox(label="Alicja AI:"),
    css="footer {visibility: hidden}",
    allow_flagging=('never'),
)
ui.queue()
ui.launch(server_name="0.0.0.0", server_port=80)
app = gr.mount_gradio_app(app, ui, path='/mypath')