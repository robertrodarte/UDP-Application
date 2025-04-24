import socket
import threading
from cryptography.fernet import Fernet

# Generate or use a predefined symmetric key
key = Fernet.generate_key()

# Save the key to a file
with open("key.key", "wb") as key_file:
    key_file.write(key)

# Load the key from the file
with open("key.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)


SERVER_IP = '0.0.0.0'  # Bind to all interfaces
SERVER_PORT = 12347
BUFFER_SIZE = 1024

# Set to keep track of clients
clients = set()

# Broadcast message to all connected clients except the sender
def broadcast_message(sock, message, exclude_addr=None):
    for client in clients:
        if client != exclude_addr:
            try:
                encrypted_message = cipher.encrypt(message.encode())
                sock.sendto(encrypted_message, client)
            except Exception as e:
                print(f"Error sending message to {client}: {e}")

# Client handler function
def handle_client(sock):
    while True:
        try:
            message, addr = sock.recvfrom(BUFFER_SIZE)
            decrypted_message = cipher.decrypt(message).decode()
            print(f"[{addr}] {decrypted_message}")
            #broadcast_message(sock, decrypted_message, exclude_addr=addr)
        except Exception as e:
            print(f"Error receiving message: {e}")

# Main server setup
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"Server started on {SERVER_IP}:{SERVER_PORT}")

    while True:
        try:
            message, addr = sock.recvfrom(BUFFER_SIZE)
            if addr not in clients:
                clients.add(addr)
                print(f"New client joined: {addr}")
            decrypted_message = cipher.decrypt(message).decode()
            print(f"[{addr}] {decrypted_message}")
            broadcast_message(sock, decrypted_message, exclude_addr=addr)
        except Exception as e:
            print(f"Error in server: {e}")

# Client chat function
def start_client(username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Type your messages below:")
    while True:
        try:
            message = input()
            encrypted_message = cipher.encrypt(f"{username}: {message}".encode())
            sock.sendto(encrypted_message, (SERVER_IP, SERVER_PORT))
        except Exception as e:
            print(f"Error sending message: {e}")

# Start the receiving thread
#threading.Thread(target=handle_client, daemon=True).start()

if __name__ == "__main__":
    mode = input("Start server or client? (s/c): ").strip().lower()
    if mode == 's':
        start_server()
    elif mode == 'c':
        username = input("Enter your username: ")
        start_client(username)
    else:
        print("Invalid option. Please enter 's' for server or 'c' for client.")