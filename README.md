
# Client Server chat (messenger) with encryption.
Secure client-server chat application using raw socket encryption without SSL/TLS certificates over TCP/IP sockets using C.
- Communication encryption Used :
  - RSA (2048-bit) for secure key exchange
  - AES-128 for fast, efficient message encryption
  - Proper IV management for cryptographic security
- Components
  - multithreads in both client and servers: one for receiving and the other for sending.
  - a portable crypto library (used for raw text encryption/decryption).

## Without encryption
  <img width="1280" alt="shell" src="https://github.com/user-attachments/assets/981b795b-22a6-43bd-87e3-dec9d2788180" />
  

  <img width="1020" alt="wireshark1" src="https://github.com/user-attachments/assets/8182bce7-870f-4df8-8a63-e6e503afada4" />
  <img width="1023" alt="wireshark2" src="https://github.com/user-attachments/assets/1312d0d5-5ab8-45f6-9956-c223c6a80569" />



## With encryption

<img width="1280" alt="shell2" src="https://github.com/user-attachments/assets/61dad704-4184-4d66-9add-383f42a21f40" />
<img width="1280" alt="wireshark3" src="https://github.com/user-attachments/assets/54422e53-8520-43cc-88a8-ffbeeef2a7ba" />
<img width="1278" alt="wireshark4" src="https://github.com/user-attachments/assets/11cb693e-5e01-4231-8894-b1ef88d0c7ac" />




## How it works ?

```mermaid
sequenceDiagram
    participant Client
    participant Server

    Note over Server: Generate RSA key pair (private & public)
    Note over Client: Generate symmetric AES key

    Client->>Server: Connect to server
    Server->>Client: Send public key

    Note over Client: Encrypt symmetric key<br/>using server's public key
    Client->>Server: Send encrypted symmetric key

    Note over Server: Decrypt symmetric key<br/>using server's private key
    Note right of Server: Now both client and server<br/>have the same symmetric key

    Note over Client,Server: For each message:
    Note over Client: Generate random IV
    Note over Client: Encrypt message with<br/>IV + symmetric key
    Client->>Server: Send IV + encrypted message
    Note over Server: Decrypt message with<br/>IV + symmetric key

    Note over Server: Generate random IV
    Note over Server: Encrypt message with<br/>IV + symmetric key
    Server->>Client: Send IV + encrypted message
    Note over Client: Decrypt message with<br/>IV + symmetric key
```

## how to run it
for server :

    gcc server.c  -lcrypto -o server && ./server 
for client 

    gcc client.c -lcrypto -o client && ./client

## Need to add

 - Multi-users (clients) , instead of only one client. (group of chat).
 - Optimize it : using stack instead of global variables.
 - Also im thinking about integrating some asm code.
