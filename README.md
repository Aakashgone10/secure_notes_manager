# Secure Notes Manager

**Author:**  
- Gone Akash   

## Introduction

The **Secure Notes Manager** is a client-server system designed to allow clients to securely manage their notes, ensuring the confidentiality, integrity, and availability of their data. This project employs a robust authentication mechanism and encryption techniques to protect user privacy.

### Key Features
- **Confidentiality**: Only authorized users can access and modify their notes using symmetric key encryption.
- **Integrity**: The project uses AES encryption  with a random initialization vector, ensuring data is both secure and resistant to tampering.
- **No Key Exchange**: The symmetric key is generated and stored on the client's side, eliminating the need for key exchange.
- **Data Privacy**: Even if the server is compromised, the data remains secure due to the end-to-end encryption.

## Objectives

- Ensure user privacy even in the event of a server breach.
- Secure user authentication with salted hashed passwords to avoid collisions.
- Encrypt data using symmetric key encryption (AES ) without key exchange.

## Implementation and Results Analysis

The system architecture consists of a **client-server model** implemented using **BSD sockets**. The **Crypto++ library** is used for encryption, decryption, key generation, and salted hashing (SHA-512).

### Authentication
- User credentials are stored in a server database, which includes a username, salt string, and hashed password.
- The server maintains separate folders for each user, storing their notes securely.

### Encryption
- **AES **: Data is encrypted with AES Algorithm with CBC Mode, introducing randomness with an initialization vector.
- **Base64 Encoding**: To prevent transmission errors, encrypted data is encoded to ASCII characters using Base64.

### User Interaction
- The client program generates a symmetric key during signup, which is stored on the client’s device. The key is used for encrypting and decrypting notes, ensuring no key exchange is needed.

### Data Storage
- User files are stored in the server's database, organized by username. During authentication, the server verifies hashed passwords by comparing them with stored values, ensuring secure access.

## Conclusion

The Secure Notes Manager ensures that clients can securely manage their notes, with a focus on data confidentiality, integrity, and availability. The system is designed for efficiency, with no need for key exchange, robust authentication, and minimal transmission errors.

### Key Learnings
- **Salted Hashing**: Generated unique salt strings for each user and calculated SHA-512 hashes using the Crypto++ library.
- **AES Encryption**: Implemented AES encryption in CBC mode for secure data storage and transmission.
- **Encoding**: Used Base64 encoding to minimize transmission errors during data transfer.

## Source Code

- **Client Implementation**: [Client.cpp](#)
- **Server Implementation**: [Server.cpp](#)

## References

1. [Crypto++ Library](https://cryptopp.com)
2. Cryptography and Network Security Principles by William Stallings
