import gradio as gr
import openai, config
from fastapi import FastAPI
import os
import asyncio

openai.api_key = config.OPENAI_API_KEY

app = FastAPI()
@app.get("/")
async def transcribe(audio=None, text=None):
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
    
        return chat_transcript
        
    
    
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
    
        return chat_transcript
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
