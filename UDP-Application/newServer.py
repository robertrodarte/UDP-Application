import socket
import base64
import logging
import threading
from utils.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

logging.basicConfig(
    filename="Logging.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Server: %(message)s",
)


class Server:
    def __init__(self, server_addr: str = "localhost", server_port: int = 12345):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((server_addr, server_port))
        self.clients = {}
        self.messages = []  # Stores received messages
        logging.info("Server initialized and waiting for connections...")

    def display_gui(self):
        """Displays the server's state in the terminal."""
        print("\033[H\033[J", end="")  # Clear the screen
        print("\n====================================")
        print("=*=*=*=*=* WELCOME SERVER *=*=*=*=*=")
        print("====================================\n")
        print("--------- Connected Clients:--------")
        print("------------------------------------")
        for client in self.clients.keys():
            print(f"(\033[1;34m{client}\033[0m)")
        print("\n-------- Received Messages: --------")
        print("------------------------------------")
        for msg in self.messages[-10:]:  # Display the last 10 messages
            print(f"\033[1;32m{msg}\033[0m")
        print("\nWaiting for messages...\n", flush=True)

    def verify_and_decrypt_message(self, data, aes_key):
        """Verifies the HMAC and decrypts the message."""
        try:
            logging.info("Verifying HMAC..")
            message_with_hmac = data.decode()
            encrypted, hmac = message_with_hmac.split(":")
            verified_hmac = verify_hmac(aes_key, encrypted, hmac)
            if not verified_hmac:
                logging.error(f"HMAC verification failed")
                return None
            logging.info(f"HMAC verified successfully.")
            decrypted = decrypt_with_aes(aes_key, encrypted)
            return decrypted
        except Exception as e:
            logging.error(f"Error during message verification/decryption: {e}")
            return None

    def handle_messages(self):
        """Handle incoming messages from clients."""
        while True:
            data, addr = self.sock.recvfrom(4096)
            logging.info(f"Received data from {addr}")

            # Unpack the received packet
            try:
                message_data = data.decode()
                if ":" not in message_data:
                    logging.warning("Malformed message received.")
                    continue

                type_str, content = message_data.split(":", 1)
                message_type = int(type_str)
            except Exception as e:
                logging.error(f"Failed to parse message: {e}")
                continue

            if message_type == 0:
                logging.info(f"Message type 0 received from {addr}")
                # Key exchange
                self.handle_key_exchange(addr, content)
            elif message_type == 1:
                logging.info(f"Message type 1 received from {addr}")
                logging.info(f"Raw content: {content}")
                if addr not in self.clients:
                    logging.warning(f"Client {addr} not found.")
                    continue

                encrypted, hmac = content.split(":")
                aes_key = self.clients[addr]

                if not verify_hmac(aes_key, encrypted, hmac):
                    logging.warning("HMAC verification failed.")
                    continue

                decrypted = decrypt_with_aes(aes_key, encrypted)
                self.messages.append(f"{addr}: {decrypted}")
                self.display_gui()

                # Acknowledge
                self.sock.sendto("ACK".encode(), addr)

                # Broadcast to others
                for other_addr, other_key in self.clients.items():
                    if other_addr == addr:
                        continue
                    re_encrypted = encrypt_with_aes(other_key, decrypted)
                    new_hmac = generate_hmac(other_key, re_encrypted)
                    final_message = f"{re_encrypted}:{new_hmac}"
                    self.sock.sendto(final_message.encode(), other_addr)
            else:
                logging.warning(f"Unknown message type {message_type}")

    def handle_key_exchange(self, addr, message):
        """Handles the key exchange with the client."""
        try:
            rsa_pub_key = base64.b64decode(message)
            aes_key = generate_aes_key()
            logging.info(f"Generated AES key for {addr}")
            encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)
            logging.info(f"Encrypted AES key for {addr}")
            self.sock.sendto(base64.b64encode(encrypted_key), addr)
            self.clients[addr] = aes_key
            self.messages.append(f"Key exchanged with {addr}")
            logging.info(f"Key exchanged with {addr}")
            self.display_gui()
        except Exception as e:
            logging.error(f"Error during key exchange with {addr}: {e}")

    def start(self):
        """Start the server to handle incoming messages."""
        # Initial GUI display
        self.display_gui()
        self.handle_messages()


def main():
    server = Server()
    server.start()


if __name__ == "__main__":
    main()
