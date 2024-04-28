import os
import socket
import json
import sqlite3
import base64
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Connect to database
conn = sqlite3.connect('EHR.db')
cursor = conn.cursor()
# AES Key Storage Path
aes_key_file_path = 'H:/PycharmProjects/ABE/server/pass.key'

# AES Key Handling
def generate_aes_key(key_length=32):
    return os.urandom(key_length)

def store_aes_key_to_file(key, aes_key_file_path):
    with open(aes_key_file_path, 'wb') as key_file:
        key_file.write(key)

def get_aes_key(aes_key_file_path):
    if not os.path.exists(aes_key_file_path):
        key = generate_aes_key()
        store_aes_key_to_file(key, aes_key_file_path)
    with open(aes_key_file_path, 'rb') as key_file:
        return key_file.read()

# Get or generate AES key
aes_key = get_aes_key(aes_key_file_path)

def encrypt(data, key, role):
    if role.lower() != 'doctor':  # Replace with your role logic
        raise ValueError("Unauthorized role")
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def handle_request(data):
    action = data.get('action')
    
    if action == 'login':
        return handleLogin(data)
    elif action == 'signup':
        return handleSignUp(data)
    else:
        return json.dumps({'error': 'Invalid action'}), 400


def handleLogin(request):
    """Check if valid credentaisl are given.

    If so return a login token or else notify the client
    """
    username = request.get('username')
    password = request.get('password')
    cursor.execute('SELECT * FROM USERS WHERE username = ? AND password = ?',
                   (username, password))
    exists = cursor.fetchone()
    if exists:
        return json.dumps({'success': username}), 200
    else:
        return json.dumps({'error': 'Invalid username or password'}), 401


def handleSignUp(request):
    """Add user to database.

    If user exists, notify the client
    """
    username = request.get('username')
    password = request.get('password')
    role = request.get('role')
    cursor.execute("SELECT MAX(user_id) FROM Users")
    maxUserId = cursor.fetchone()[0]
    newUserId = maxUserId + 1 if maxUserId is not None else 1

    try:
        cursor.execute("INSERT INTO Users (user_id, username, password, role)\
        VALUES (?, ?, ?, ?)", (newUserId, username, password, role))
        conn.commit()
        return json.dumps({'message': 'User signed up successfully'}), 200
    except sqlite3.IntegrityError:
        return json.dumps({'error': 'Username already exists'}), 400

def handleGetData(request):
    query = request.get('query')
    role = request.get('role')
    firstname = request.get('uname').split('.')[0]
    if role == 'patient' or role == 'doctor':
        if firstname not in query:
            return json.dumps({'error': 'Invalid query.'}), 400
    try:
        cursor.execute(query)
        res = cursor.fetchall()
        encrypted_res = encrypt(str(res), aes_key, role)
        return json.dumps({'message': encrypt(res, encrypted_res)}), 200
    except sqlite3.IntegrityError:
        return json.dumps({'error': 'Invalid query.'}), 400
    except ValueError as e:
        return json.dumps({'error': str(e)}), 403

def main():
    """Entry point for server."""
    server_address = ('localhost', 8888)
    buffer_size = 1024

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(server_address)
        server_socket.listen(5)
        print('Server is listening on', server_address)

        while True:
            client_socket, client_address = server_socket.accept()
            print('Connection from', client_address)

            data = client_socket.recv(buffer_size).decode()
            print('Received data:', data)

            if data:
                request = json.loads(data)
                action = request.get('action')

                if action == 'login':
                    response, status = handleLogin(request)
                elif action == 'signup':
                    response, status = handleSignUp(request)
                elif action == 'getData':
                    response, status = handleGetData(request)
                else:
                    response = json.dumps({'error': 'Invalid action'}), 400
                    # status = 400
                client_socket.sendall(response.encode())
                print('Response sent:', response)

            client_socket.close()


if __name__ == '__main__':
    main()
