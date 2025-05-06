import socket
import base64
import logging
import threading
from utils.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_hmac,
    verify_hmac,
)

logging.basicConfig(
    filename="Logging.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Client: %(message)s",
)

## Packet Structure:
# Field 1: Client ID (4 bytes)
# Field 2: Message Type (1 byte) - 0 for key exchange, 1 for message
# Field 3: Message Length (2 bytes) - Length of the message in bytes
# Field 4: Message (variable length) - The actual message content


class Client:
    def __init__(self, server_addr: str = "localhost", server_port: int = 12345):
        logging.info("Initializing client...")
        self.server_ip = (server_addr, server_port)
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.private_key = None
        self.aes_key = None
        self.client_id = 1
        self.ack_event = threading.Event()
        self.messages = []  # Stores received messages
        self.receive_thread = threading.Thread(
            target=self.receive_messages, daemon=True
        )
        self.exchange_key()
        self.receive_thread.start()

    def start(self):
        while True:
            self.display_gui()
            data = input()
            if not self.aes_key:
                logging.info("Waiting for key exchange to complete")
                print("Waiting for key exchange to complete...")
                continue

            encrypted = encrypt_with_aes(self.aes_key, data)
            hmac = generate_hmac(self.aes_key, encrypted)
            message = f"{encrypted}:{hmac}"
            self.send_data(1, message, data, destination_ip=self.server_ip)

    def send_data(self, message_type, message, plaintext=None, destination_ip=None):
        retries = 3
        ack_received = False
        for attempt in range(retries):
            try:
                self.ack_event.clear()
                final_message = f"{message_type}:{message}"
                logging.info(f"Sending to server: {message_type}:{final_message}")
                self.sock.sendto(final_message.encode(), destination_ip)
                logging.info(f"Sent message (Attempt {attempt + 1})")

                if self.ack_event.wait(timeout=2):
                    ack_received = True
                    break
                else:
                    logging.warning(
                        f"No ACK received, retrying ({attempt + 1}/{retries})..."
                    )

            except Exception as e:
                logging.error(f"Send error: {e}")
                break

        if ack_received:
            display = plaintext if plaintext else message
            self.messages.append(f"You: {display}")
        else:
            self.messages.append("Error: Failed to send message after retries.")
        self.display_gui()

    def exchange_key(self):
        logging.info("Generating RSA keypair...")
        self.private_key, public_key = generate_rsa_keypair()
        encoded_key = base64.b64encode(public_key).decode()
        full_message = f"0:{encoded_key}"
        self.sock.sendto(full_message.encode(), self.server_ip)
        logging.info("Public key sent to server.")

    def receive_messages(self):
        while True:
            # Check if theres data to recieve
            data, _ = self.sock.recvfrom(4096)
            logging.info(f"Client: Raw incoming message: {data}")
            message = data.decode()

            if message == "ACK":
                self.ack_event.set()
                self.display_gui()
                continue

            if self.aes_key is None:
                # AES key exchange (first time)
                try:
                    logging.info(f"Client: Raw AES key message: {message}")
                    encrypted_key_bytes = base64.b64decode(message)
                    logging.info(
                        f"Client: Encrypted key (bytes): {encrypted_key_bytes.hex()}"
                    )
                    self.aes_key = decrypt_with_rsa(
                        self.private_key, encrypted_key_bytes
                    )
                    if self.aes_key:
                        logging.info(
                            f"Client: AES key successfully set: {self.aes_key.hex()}"
                        )
                        self.messages.append("AES key received and decrypted.")
                    else:
                        logging.warning("Client: Decryption returned None.")
                except Exception as e:
                    logging.error(f"Client: Exception during AES key decryption: {e}")
                    self.messages.append(f"Error decrypting AES key: {e}")
                self.display_gui()
                continue

            # Encrypted message with HMAC
            if ":" not in message:
                self.messages.append("Error: Malformed message.")
                self.display_gui()
                continue

            try:
                encrypted, hmac = message.split(":")

                if not verify_hmac(self.aes_key, encrypted, hmac):
                    self.messages.append("Error: HMAC verification failed.")
                    self.display_gui()
                    logging.error("Error: HMAC Verification Failed")
                    return

                decrypted = decrypt_with_aes(self.aes_key, encrypted)
                self.messages.append(f"Server Broadcast: {decrypted}")
            except Exception as e:
                self.messages.append(f"Error handling message: {e}")

            self.display_gui()

    def display_gui(self):
        print("\033[H\033[J", end="")  # Clear the screen
        print("\n====================================")
        print("=*=*=*=*=* WELCOME CLIENT *=*=*=*=*=")
        print("====================================\n")
        print("----------- CHAT HISTORY -----------")
        print("------------------------------------")
        for msg in self.messages[-10:]:
            if msg.startswith("You:"):
                print(f"\033[1;34m{msg}\033[0m")  # Blue
            elif msg.startswith("Server Broadcast:"):
                print(f"\033[1;32m{msg}\033[0m")  # Green
            elif msg.startswith("Error"):
                print(f"\033[1;31m{msg}\033[0m")  # Red
            else:
                print(msg)
        print("\n------------------------------------")
        print("Type your message below:\n", end="", flush=True)


def main():
    client = Client()
    client.start()


if __name__ == "__main__":
    main()
