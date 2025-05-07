# 🔐 Secure UDP Chat Application

## 🚀 How to Run the Application

> Ensure you have **Python 3** installed.

### 1. Install Requirements

```bash
pip install requirements.txt
```

### 2. Run the Application

Launch the application to choose between server or client:

```bash
python udp_application.py
```

Or run manually:

```bash
python newServer.py  # Starts the server
python newClient.py  # Starts a new client
```

---

## 🔐 Summary of Cryptographic Design Choices

### Packet Format
- Message Type: Tells the server if the message is a key exchange.
- Message: AES encrypted data being sent by the client
- HMAC: Generated HMAC for message integrity
- [Message Type | Message | HMAC]

### RSA Public/Private Key Pair

- Each client generates an RSA key pair on startup.
- The public key is sent to the server upon initial connection.

### AES Symmetric Key

- The server generates a random AES key for each client.
- This key is encrypted with the client’s RSA public key and sent back securely.

### Encrypted Communication

- Once the client decrypts the AES key with its private RSA key, all further communication is encrypted with AES.

### Message Integrity

- Each message includes an HMAC for integrity verification.
- The recipient compares the received HMAC with a locally generated one to ensure the message hasn’t been altered.

### Reliability

- Since UDP does not guarantee delivery, ACKs are used.
- The server sends an acknowledgment for every message received.
- The client retries sending a message up to three times if no ACK is received within a given timeout period.

---

## ⚙️ Assumptions and Limitations

### ✅ Assumptions

- All clients correctly generate and send RSA public keys.
- The AES key is securely exchanged and used only between a specific client-server pair.

### ⚠️ Limitations

- Prone to duplicate messages and there is no re-ordering.
- No user authentication — any client can send a public key to the server as long as packet form is correct.
- No persistent storage — messages are not saved beyond runtime.
- Only used for local use.

---

## 🖥️ User Interface and Logging

- The `udp_application.py` script provides a menu to launch either client or server.
- The GUI uses ANSI escape codes to colorize:
  - Client messages
  - Server broadcasts
  - Errors
- Chat history and a live input prompt are shown.
- All actions are logged to `Logging.txt` for debugging and traceability.

## 📖 Sphinx Documentation Steps
From the UDP Application directory run the following command to view application documentation

```bash
start ./docs/_build/html/index.html
```