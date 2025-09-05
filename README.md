# Secure-Chat-App-with-End-to-End-Encryption

Objective
- Create a private chat application with E2EE using public-key cryptography

Tools & Technologies

- Python
- Flask-SocketIO
- RSA & AES (Cryptography Library)
- SQLite (Encrypted Logs)

Mini Guide / Workflow
```
a. Generate RSA keys per user and share public keys.
b. Encrypt messages with AES, keys shared via RSA.
c. Enable real-time communication with Flask-SocketIO.
d. Store chat logs encrypted on the server.
e. Decrypt and display messages only on client side.
```
Deliverables

- Secure chat app with E2EE
- Real-time encrypted communication
- Encrypted logs stored on server
- Client-side decryption only

Security Benefits

- Ensures privacy: Server cannot read messages
- Protects against eavesdropping
- Messages stored only as ciphertext
- Private keys never leave the client
