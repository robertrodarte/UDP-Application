import socket
import threading

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
                sock.sendto(message.encode(), client)
            except Exception as e:
                print(f"Error sending message to {client}: {e}")

# Server function that runs as a separate thread
def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"Server started on {SERVER_IP}:{SERVER_PORT}")

    while True:
        try:
            print(f"New client joined: {addr}")
            print(f"[Server Received from {addr}] {message.decode()}")
            broadcast_message(sock, message.decode(), exclude_addr=addr)
        except Exception as e:
            print(f"Error in server: {e}")

# Client chat function
def client(username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Type your messages below:")

    def receive_messages():
        while True:
            try:
                message, addr = sock.recvfrom(BUFFER_SIZE)
                print(f"[{addr}] {message.decode()}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    threading.Thread(target=receive_messages, daemon=True).start()

    while True:
        try:
            message = input("You: ")
            sock.sendto(f"{username}: {message}".encode(), (SERVER_IP, SERVER_PORT))
        except Exception as e:
            print(f"Error sending message: {e}")

# Combined mode: runs both server and client
def combined_mode(username):
    threading.Thread(target=server, daemon=True).start()
    client(username)

if __name__ == "__main__":
    mode = input("Start server, client, or both? (s/c/b): ").strip().lower()
    if mode == 's':
        server()
    elif mode == 'c':
        username = input("Enter your username: ")
        client(username)
    elif mode == 'b':
        username = input("Enter your username: ")
        combined_mode(username)
    else:
        print("Invalid option. Please enter 's' for server, 'c' for client, or 'b' for both.")