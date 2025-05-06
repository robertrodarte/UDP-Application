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

aes_key = None
messages = []  # Stores received messages

## Packet Structure:
# Field 1: Client ID (4 bytes)
# Field 2: Message Type (1 byte) - 0 for key exchange, 1 for message
# Field 3: Message Length (2 bytes) - Length of the message in bytes
# Field 4: Message (variable length) - The actual message content


class Client:
    def __init__(self, server_addr: str = "localhost", server_port: int = 4096):
        # Initialize the client with server IP and port
        logging.info("Initializing client...")
        self.server_ip = (server_addr, server_port)
        self.server_port = server_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.private_key = None
        self.aes_key = None
        self.client_id = 1

        # Start ack event
        self.ack_event = threading.Event()

        # Start threading for receiving messages
        self.receive_thread = threading.Thread(
            target=self.receive_messages, daemon=True
        ).start()

        # Send packet, communicating to server you are sending an RSA key
        self.exchange_key()

    def start_client(self):
        while True:
            self.display_gui()
            data = input()
            logging.info(f"Sending message: {data}")
            if not aes_key:
                print("Waiting for key exchange to complete...")
                continue
            packed_data = self.pack_data(first_exchange=0, data=data)
            self.send_data(packed_data=packed_data, destination_ip=self.server_ip)

    def pack_data(self, first_exchange, data):
        # Set client id
        client_id = self.client_id
        # Determine type of message
        if first_exchange:
            message_type = 1
        else:
            message_type = 0
            # Encode with AES
            message = data.encrypt_with_aes()
        # Get message length
        message_length = message.length()
        # Pack and return
        packed_data = [client_id, message_type, message_length, message]
        return packed_data

    def unpack_data(packed_data):
        # Convert from binary
        packed_data = packed_data.decode()
        client_id = packed_data[0]
        message_type = packed_data[1]
        message_length = packed_data[2]
        message = packed_data[3]
        unpacked_data = [client_id, message_type, message_length, message]
        return unpacked_data

    def send_data(self, packed_data, destination_ip):
        aes_data = encrypt_with_aes(self.aes_key, packed_data)
        aes_hmac = generate_hmac(aes_key, aes_data)
        final_message = f"{aes_data}:{aes_hmac}"
        logging.info("Encrypted message and generated hmac")

        retries = 3
        ack_received = False
        for attempt in range(retries):
            try:
                self.ack_event.clear()
                self.sock.sendto(final_message, destination_ip)
                logging.info(f"Sent message (Attempt {attempt + 1})")

                if self.ack_event.wait(
                    timeout=2
                ):  # This waits without touching the socket
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
            messages.append(f"You: {packed_data[3]}")
        else:
            messages.append("Error: Failed to send message after retries.")
        self.display_gui()
        logging.info(f"Packed data sent to {destination_ip}")

    def exchange_key(self):
        logging.info("Generating RSA keypair...")
        # Generate RSA keys and send public key to server
        self.private_key, public_key = generate_rsa_keypair()
        # Encode public key
        data = base64.b64encode(public_key)
        # Create the packet being sent
        packed_data = self.pack_data(first_exchange=True, data=data)
        # Send the packet
        self.send_data(packed_data=packed_data, destination_ip=self.server_ip)
        logging.info("Public key sent to server.")

    def display_gui():
        global messages
        print("\033[H\033[J", end="")  # Clear the screen
        print("\n====================================")
        print("=*=*=*=*=* WELCOME CLIENT *=*=*=*=*=")
        print("====================================\n")
        print("----------- CHAT HISTORY -----------")
        print("------------------------------------")
        for msg in messages[-10:]:
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

    def receieve_messages(self, sock, private_key):
        global aes_key, messages
        while True:
            try:
                # Check if theres data to recieve
                packed_data, _ = sock.recvfrom(self.server_port)

                # Unpack data
                data = self.unpack_data(packed_data=packed_data)
                # Get message from packet
                message = data[3]

                # Handle acknowledgment
                if message == "ACK":
                    self.ack_event.set()
                    logging.info("Received acknowledgment from server.")
                    continue

                # Handle AES key exchange
                if aes_key is None:
                    try:
                        encrypted_key = base64.b64decode(message)
                        aes_key = decrypt_with_rsa(private_key, encrypted_key)
                        messages.append("You: Received and decrypted AES key.")
                        logging.info("AES key received and decrypted successfully.")
                        self.display_gui()
                    except Exception as e:
                        logging.error(f"Error decrypting AES key: {e}")
                        self.display_gui()
                    continue

                # Handle regular messages
                try:
                    message_with_hmac = message
                    if ":" not in message_with_hmac:
                        raise ValueError("Invalid message format received.")
                    encrypted, hmac = message_with_hmac.split(":")
                    if not verify_hmac(aes_key, encrypted, hmac):
                        logging.error("HMAC verification failed.")
                        messages.append("Error: HMAC verification failed.")
                        self.display_gui()
                        continue
                    decrypted = decrypt_with_aes(aes_key, encrypted)
                    messages.append(f"Server Broadcast: {decrypted}")
                    logging.info(f"Decrypted Broadcast Successfully: {decrypted}")
                    self.display_gui()
                except Exception as e:
                    logging.error(f"Error receiving message: {e}")
                    messages.append(f"Error receiving message: {e}")
                    self.display_gui()

            except Exception as e:
                logging.error(f"Socket error: {e}")


def main():
    client = Client()
    client.start_client()


if __name__ == "__main__":
    main()
# Check database if client exist
