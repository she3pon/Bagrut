import socket
import threading
import pickle
import secrets
import hashlib
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import random
import time

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def generate_dh_params(key_length=2048):
    prime = getPrime(key_length)
    generator = random.randint(2, prime - 1)
    return prime, generator

def perform_dh_exchange(client_sock):
    prime, generator = generate_dh_params()

    server_private_key = random.randint(2, prime - 2)
    server_public_key = pow(generator, server_private_key, prime)

    client_sock.send(f"{prime},{generator},{server_public_key}".encode())

    client_public_key = int(client_sock.recv(2000000).decode())

    shared_secret = pow(client_public_key, server_private_key, prime)
    shared_secret_bytes = long_to_bytes(shared_secret)

    aes_key = shared_secret_bytes[:16]
    return aes_key

def handle_dh_exchange(client_sock):
    global aes_key
    aes_key = perform_dh_exchange(client_sock)
    print(f"Diffie-Hellman key exchange completed. AES key: {aes_key.hex()}")
    return aes_key

def generate_code():
    return random.randint(1000, 9999)

class MessageParser:
    def __init__(self, reply):
        reply = reply.split(b",")
        try:
            self.length = reply[0]
        except:
            pass
        try:
            self.method = reply[1]
        except:
            pass
        try:
            self.username = reply[2]
        except:
            pass
        try:
            self.password = reply[3]
        except:
            pass
        try:
            self.email = reply[4]
        except:
            pass
        try:
            self.text = reply[5]
        except:
            pass

class User:
    def __init__(self, username, password, email, salt, pepper):
        self.username = username
        self.password = password
        self.email = email
        self.salt = salt
        self.pepper = pepper
        self.messages = []

def hash_password(password, salt, pepper):
    salted_password = password.decode() + pepper + str(salt)
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed_password

def generate_salt(length=16):
    return secrets.token_hex(length)

def create_user(username, password, email):
    salt = generate_salt(17)
    hashed_password = hash_password(password, salt, pepper)
    user = User(username, hashed_password, email, salt, pepper)
    return user

def save_to_pickle(users, filename):
    try:
        with open(filename, 'wb') as file:
            pickle.dump(users, file)
        print("User objects saved to pickle file successfully.")
    except Exception as e:
        print("Error occurred while saving to pickle:", e)

def load_from_pickle(filename):
    try:
        with open(filename, 'rb') as file:
            users = pickle.load(file)
        return users
    except FileNotFoundError:
        print("Pickle file not found.")
        return {}
    except Exception as e:
        print("Error occurred while loading from pickle:", e)
        return {}

def check_credentials(username, password, filename):
    user_dict = load_from_pickle(filename)
    if username in user_dict:
        user = user_dict[username]
        if hash_password(password, user.salt, pepper) == user.password:
            return True
    return False

def get_email(username, filename):
    user_dict = load_from_pickle(filename)
    if username in user_dict:
        user = user_dict[username]
        return user.email
    return "User not found in database"

def get_user(username, password, filename):
    user_dict = load_from_pickle(filename)
    if username in user_dict:
        user = user_dict[username]
        if hash_password(password, user.salt, pepper) == user.password:
            return user
    return None

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ciphertext

def decrypt_message(ciphertext, key):
    iv = b64decode(ciphertext[:24])
    ciphertext_bytes = b64decode(ciphertext[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
    return decrypted_message.decode('utf-8')

def generate_key_pair():
    global private_key, public_key
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key

def decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key):
    rsa_key = RSA.import_key(rsa_private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return decrypted_aes_key

def encrypt_aes_key_with_rsa(aes_key, rsa_public_key):
    rsa_key = RSA.import_key(rsa_public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def send_rsa_key(client):
    public_key = generate_key_pair()
    client.send(public_key)

def send_public_key(client_socket, public_key):
    key_data = public_key.export_key()
    client_socket.send(key_data)

def send_encrypted_message(client, message):
    encrypted_message = encrypt_message(message, aes_key)
    client.send(encrypted_message.encode())

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import ssl
from email.message import EmailMessage

EMAIL_SENDER = "your_email@example.com"
EMAIL_PASSWORD = "your_email_password"

def send_email(email_receiver):
    email = EmailMessage()
    email['From'] = EMAIL_SENDER
    email['To'] = email_receiver
    email['Subject'] = 'Reset Password Verification'

    email.set_content(f'Your verification code is {generate_code()} It will expire in 10 minutes')
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(EMAIL_SENDER, EMAIL_PASSWORD)