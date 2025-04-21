import os
import subprocess
import time
import socket
import asyncio
from threading import Thread
from typing import Dict

import aiohttp
from aiohttp_socks import ProxyConnector
from fastapi import FastAPI, Body
import uvicorn
from stem.control import Controller

import customtkinter as ctk
from dotenv import load_dotenv
from gostcrypto.gostcipher import new as cipher_new, MODE_CTR

load_dotenv()

KEY = bytes.fromhex(os.environ.get('KEY'))
IV = bytes.fromhex(os.environ.get('IV'))
TOR_PATH = os.path.join('tor', 'tor.exe')
CONTROL_PORT = os.environ.get('CONTROL_PORT')
SOCKS_PORT = os.environ.get('SOCKS_PORT')
LOCAL_PORT = os.environ.get('LOCAL_PORT')
HIDDEN_SERVICE_DIR = 'hidden_service'
TORRC_PATH = 'torrc'
TORRC = f'''SocksPort {SOCKS_PORT}
ControlPort {CONTROL_PORT}
DataDirectory ./tor_data
GeoIPFile ./tor/geoip
GeoIPv6File ./tor/geoip6
Log notice stdout
HiddenServiceDir ./{HIDDEN_SERVICE_DIR}
HiddenServicePort 80 127.0.0.1:{LOCAL_PORT}'''

with open(TORRC_PATH, 'w', encoding='utf-8') as file:
    file.write(TORRC)

app = FastAPI()
messages_callback = None

@app.post('/message')
def message(payload: Dict = Body(...)):
    try:
        crypt = GOSTCryptoMessenger(KEY, iv=IV)
        ciphertext = bytes.fromhex(payload['text'])
        decrypted = crypt.decrypt(ciphertext).decode('utf-8')

        if messages_callback:
            messages_callback('Peer', decrypted, incoming=True)
    except Exception as e:
        print(f'[!] Decryption error: {e}')
    return 'ok'

def wait_for_port(host, port, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(1)
    raise TimeoutError(f'Port {port} not opened in {timeout} seconds.')

def start_tor():
    process = subprocess.Popen(
        [TOR_PATH, '-f', TORRC_PATH],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    wait_for_port('127.0.0.1', int(SOCKS_PORT))

    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if 'Done' in output:
            print('[✔] Tor has started successfully.')
            break

def get_own_onion():
    with Controller.from_port(port=int(CONTROL_PORT)) as controller:
        controller.authenticate()
        with open(os.path.join(HIDDEN_SERVICE_DIR, 'hostname')) as f:
            return f.read().strip()

def start_server():
    uvicorn.run(app, host='127.0.0.1', port=int(LOCAL_PORT), log_level='error')


async def send_message_to_peer(target_onion, msg):
    url = f'http://{target_onion}/message'
    connector = ProxyConnector.from_url(f'socks5://127.0.0.1:{SOCKS_PORT}')

    crypt = GOSTCryptoMessenger(KEY, iv=IV)
    ciphertext, _ = crypt.encrypt(msg.encode())

    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.post(url, json={
                'text': ciphertext.hex()
            }) as resp:
                if resp.status != 200:
                    print('[!] Error')
        except Exception as e:
            print(f'[X] Error: {e}')

class MessengerApp:
    def __init__(self, root):
        self.send_button = None
        self.message_entry = None
        self.chat_display = None
        self.name_label = None
        self.chat_frame = None
        self.connect_button = None
        self.onion_entry = None
        self.onion_label = None
        self.connect_frame = None
        self.root = root
        self.root.title('Крипто-мессенджер')
        self.root.geometry('500x600')
        self.root.resizable(False, False)
        self.target_onion = None
        self.show_connect_screen()

    def show_connect_screen(self):
        try:
            my_onion = get_own_onion()
            self.root.clipboard_clear()
            self.root.clipboard_append(my_onion)
            self.root.update()
        except Exception as e:
            print(e)

        self.connect_frame = ctk.CTkFrame(self.root)
        self.connect_frame.pack(pady=100, padx=50, fill='both', expand=True)

        self.onion_label = ctk.CTkLabel(self.connect_frame, text='Введите onion-адрес:')
        self.onion_label.pack(pady=10)

        self.onion_entry = ctk.CTkEntry(self.connect_frame, width=350)
        self.onion_entry.pack(pady=10)

        self.connect_button = ctk.CTkButton(self.connect_frame, text='Подключиться', command=self.connect)
        self.connect_button.pack(pady=20)

    def connect(self):
        self.target_onion = self.onion_entry.get().strip()
        if not self.target_onion:
            return

        self.connect_frame.pack_forget()
        self.open_chat_window()

    def open_chat_window(self):
        self.chat_frame = ctk.CTkFrame(self.root)
        self.chat_frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.root.title(f'Чат')

        top_bar = ctk.CTkFrame(self.chat_frame, fg_color='transparent')
        top_bar.pack(fill='x', pady=(0, 10))

        short_address = f'{self.target_onion[:10]}...{self.target_onion[-20:]}'
        self.name_label = ctk.CTkLabel(top_bar, text=short_address, font=('Arial', 16))
        self.name_label.pack(padx=10, anchor='w')

        self.chat_display = ctk.CTkScrollableFrame(self.chat_frame, width=400, height=450)
        self.chat_display.pack(pady=5, fill='both', expand=True)

        input_row = ctk.CTkFrame(self.chat_frame, fg_color='transparent', height=40)
        input_row.pack(fill='x', pady=(0, 10), padx=5)
        input_row.grid_columnconfigure(0, weight=1)

        self.message_entry = ctk.CTkEntry(input_row)
        self.message_entry.grid(row=0, column=0, sticky='ew')
        self.message_entry.bind('<Return>', lambda e: self.send_message())

        self.send_button = ctk.CTkButton(input_row, text='→', width=40, command=self.send_message)
        self.send_button.grid(row=0, column=1, padx=(5, 0))

        self.add_message('System', 'Успешно подключено', incoming=True)

    def send_message(self):
        msg = self.message_entry.get().strip()
        if msg:
            self.add_message('You', msg, incoming=False)
            self.message_entry.delete(0, 'end')
            Thread(target=lambda: asyncio.run(send_message_to_peer(self.target_onion, msg)), daemon=True).start()

    def add_message(self, _, msg, incoming=True):
        color = '#2f80ed' if not incoming else '#4f4f4f'
        justify = 'right' if not incoming else 'left'
        anchor = 'e' if not incoming else 'w'

        bubble = ctk.CTkLabel(
            self.chat_display,
            text=msg,
            fg_color=color,
            corner_radius=10,
            justify=justify,
            text_color='white',
            wraplength=300,
            padx=10,
            pady=5
        )
        bubble.pack(anchor=anchor, pady=4, padx=6)
        self.chat_display.update_idletasks()
        self.chat_display._parent_canvas.yview_moveto(1.0)

class GOSTCryptoMessenger:
    def __init__(self, key: bytes, mode=MODE_CTR, iv: bytes = None):
        self.key = bytearray(key)
        self.mode = mode
        self.iv = bytearray(iv) if iv else os.urandom(8)
        self._cipher = self._init_cipher()

    def _init_cipher(self):
        return cipher_new(
            'kuznechik',
            self.key,
            self.mode,
            init_vect=self.iv
        )

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        self._cipher = self._init_cipher()
        encrypted = self._cipher.encrypt(bytearray(plaintext))
        return bytes(encrypted), bytes(self.iv)

    def decrypt(self, ciphertext: bytes, iv: bytes = None) -> bytes:
        iv_to_use = bytearray(iv or self.iv)
        cipher = cipher_new('kuznechik', self.key, self.mode, init_vect=iv_to_use)
        decrypted = cipher.decrypt(bytearray(ciphertext))
        return bytes(decrypted)

def run_app():
    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('blue')

    root = ctk.CTk()
    app_ = MessengerApp(root)

    global messages_callback
    messages_callback = app_.add_message

    root.mainloop()

def main():
    Thread(target=start_tor, daemon=True).start()
    Thread(target=start_server, daemon=True).start()
    run_app()

if __name__ == '__main__':
    asyncio.run(asyncio.to_thread(main))
