import socket
import secrets
from hashlib import sha256

# Prime number (public) and base (public)
prime = 23  # A small prime number for demonstration
base = 5    # A primitive root modulo prime

# Function to generate public and private keys
def generate_keys():
    private_key = secrets.randbelow(prime)
    public_key = pow(base, private_key, prime)
    return private_key, public_key

# Function to calculate shared secret
def calculate_shared_secret(their_public, my_private):
    return pow(their_public, my_private, prime)

# Server Code
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server listening on port 65432")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Generate server's keys
    private_key, public_key = generate_keys()
    print(f"Server public key: {public_key}")
    conn.send(str(public_key).encode())

    # Receive client's public key
    client_public = int(conn.recv(1024).decode())
    print(f"Received client public key: {client_public}")

    # Calculate shared secret
    shared_secret = calculate_shared_secret(client_public, private_key)
    symmetric_key = sha256(str(shared_secret).encode()).hexdigest()
    print(f"Server shared secret: {shared_secret}")
    print(f"Symmetric key (hashed): {symmetric_key}")
    conn.close()

# Client Code
def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Generate client's keys
    private_key, public_key = generate_keys()
    print(f"Client public key: {public_key}")

    # Receive server's public key
    server_public = int(client_socket.recv(1024).decode())
    print(f"Received server public key: {server_public}")

    # Send client's public key
    client_socket.send(str(public_key).encode())

    # Calculate shared secret
    shared_secret = calculate_shared_secret(server_public, private_key)
    symmetric_key = sha256(str(shared_secret).encode()).hexdigest()
    print(f"Client shared secret: {shared_secret}")
    print(f"Symmetric key (hashed): {symmetric_key}")
    client_socket.close()

if __name__ == '__main__':
    mode = input("Start server or client? (s/c): ").strip().lower()
    if mode == 's':
        server()
    elif mode == 'c':
        client()
    else:
        print("Invalid option. Please enter 's' for server or 'c' for client.")