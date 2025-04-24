#socket: Provides the low-level networking interface.
#threading: Allows the server and client to handle sending and receiving messages concurrently.
import socket
import threading

#SERVER_IP: ‘0.0.0.0’ means the server listens on all available network interfaces.
#SERVER_PORT: The port number used for communication.
#BUFFER_SIZE: The size of the data chunks received (1 KB).
SERVER_IP = '0.0.0.0'  # Bind to all interfaces
SERVER_PORT = 12347
BUFFER_SIZE = 1024

# Set to keep track of clients. Uses a Python set to keep track of 
#connected clients, which prevents duplicates and allows quick 
#membership checks.

clients = set()

# Broadcast message to all connected clients except the sender
#Parameters:
#sock: The UDP socket used for communication.
#message: The message to broadcast.
#exclude_addr: The address to exclude (typically the sender).
#Functionality:
#Iterates through the list of clients.
#Sends the message to all except the sender.
#Uses sock.sendto() to send the message over UDP.
def broadcast_message(sock, message, exclude_addr=None):
    for client in clients:
        if client != exclude_addr:
            try:
                # Directly send the plain text message
                sock.sendto(message.encode(), client)
            except Exception as e:
                print(f"Error sending message to {client}: {e}")

# Client handler function
def handle_client(sock):
    while True:
        try:
            message, addr = sock.recvfrom(BUFFER_SIZE)
            print(f"[{addr}] {message.decode()}")
            # Broadcast the plain text message
            broadcast_message(sock, message.decode(), exclude_addr=addr)
        except Exception as e:
            print(f"Error receiving message: {e}")

# Main server setup
#Creates a UDP socket using AF_INET (IPv4) and SOCK_DGRAM (UDP).
#Binds to the specified IP and port, making the server accessible.
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))
    print(f"Server started on {SERVER_IP}:{SERVER_PORT}")

#recvfrom(): Receives data from a client and gets the sender’s address.
#New Client Detection: If the client is not already in the set, it adds the client and prints a welcome message.
#Message Broadcasting: Sends the received message to all other clients.
#Error Handling: Prints an error message if any issue occurs.
    while True:
        try:
            message, addr = sock.recvfrom(BUFFER_SIZE)
            if addr not in clients:
                clients.add(addr)
                print(f"New client joined: {addr}")
            print(f"[{addr}] {message.decode()}")
            broadcast_message(sock, message.decode(), exclude_addr=addr)
        except Exception as e:
            print(f"Error in server: {e}")

# Client chat function
#Creates a UDP socket for the client to communicate with the server.

def start_client(username):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("Type your messages below:")

#Input: Takes user input.
#Send Message: Sends the message to the server using sock.sendto().
#Format: Prepends the username to the message for identification.
    while True:
        try:
            message = input()
            # Directly send the plain text message
            sock.sendto(f"{username}: {message}".encode(), (SERVER_IP, SERVER_PORT))
        except Exception as e:
            print(f"Error sending message: {e}")

#User Prompt: Asks whether to start the server or client.
#Branching: Calls the appropriate function based on user input.
#Start the server and Client in different windows
if __name__ == "__main__":
    mode = input("Start server or client? (s/c): ").strip().lower()
    if mode == 's':
        start_server()
    elif mode == 'c':
        username = input("Enter your username: ")
        start_client(username)
    else:
        print("Invalid option. Please enter 's' for server or 'c' for client.")