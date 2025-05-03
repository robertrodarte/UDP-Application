# 🔐 Secure UDP Chat Application

## 📦 Features

- **RSA (asymmetric)** and **AES (symmetric)** for encrypted communication
- **HMAC** for message authentication
- Retransmission mechanism over UDP using ACKs
- Terminal-based GUI for client and server
- Logging of all events to `Logging.txt`

---

## 🚀 How to Run

> 💡 You will need Python 3 installed to run the application.

### 1. Clone the Project

```bash
git clone https://github.com/robertrodarte/UDP-Application.git
cd UDP-Application
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Run the App

Launch the app menu (Note: Only one server can be ran at a time):

```bash
python udp_application.py
```

You'll be prompted to:

- Run as **Server**
- Run as **Client**
- Exit

You can also run directly:

- `python server.py`
- `python client.py`

## 🔐 Cryptographic Design Summary

### 🔸 Key Exchange

- Clients generate an **RSA key pair** (Public and Private).
- The **public key** is sent to the server.
- The server generates a unique **AES key** for each client.
- The AES key is encrypted with the client’s RSA public key and sent back.

### 🔸 Message Encryption

- All messages are encrypted with AES in symmetric mode.
- Each message includes:
  - The AES-encrypted text
  - An **HMAC** to verify the message's integrity

### 🔸 Message Delivery

- The server sends an `ACK` to confirm successful receipt.
- The client retries sending messages (up to 3 times) if no ACK is received within a timeout period.

---

## ⚙️ Assumptions & Limitations

### ✅ Assumptions

- Clients send a **valid RSA public key** on connection.
- Server is trusted to distribute AES keys securely.
- Messages are text-based and under 4096 bytes.

### ⚠️ Limitations

- This app uses basic ACK-based retries but does **not guarantee** delivery.
- **No authentication** — server accepts any incoming public key.
- No support for communication outside of LAN or localhost.
