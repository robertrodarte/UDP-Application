import socket
import threading

SERVER_IP = '0.0.0.0'  # Bind to all interfaces
SERVER_PORT = 65432
BUFFER_SIZE = 1024

# Server Code
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    def receive_messages():
        while True:
            try:
                message = conn.recv(BUFFER_SIZE).decode()
                if message:
                    print(f"Client: {message}")
                else:
                    print("Client disconnected.")
                    break
            except:
                print("Error receiving message.")
                break

    threading.Thread(target=receive_messages).start()

    while True:
        try:
            message = input("You: ")
            conn.send(message.encode())
        except:
            print("Error sending message.")
            break
    conn.close()

# Client Code
def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', SERVER_PORT))

    def receive_messages():
        while True:
            try:
                message = client_socket.recv(BUFFER_SIZE).decode()
                if message:
                    print(f"Server: {message}")
                else:
                    print("Server disconnected.")
                    break
            except:
                print("Error receiving message.")
                break

    threading.Thread(target=receive_messages).start()

    while True:
        try:
            message = input("You: ")
            client_socket.send(message.encode())
        except:
            print("Error sending message.")
            break
    client_socket.close()

if __name__ == '__main__':
    mode = input("Start server or client? (s/c): ").strip().lower()
    if mode == 's':
        server()
    elif mode == 'c':
        client()
    else:
        print("Invalid option. Please enter 's' for server or 'c' for client.")