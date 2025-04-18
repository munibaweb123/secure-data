# Secure Data Encryption System

This application is designed to securely store and retrieve data using unique passkeys. The data is encrypted using the Fernet symmetric encryption algorithm from the `cryptography` library. The passkey is hashed using the SHA-256 algorithm and a unique salt for each user. The hashed passkey is then used to derive a Fernet key, which is used to encrypt and decrypt the data.

## Encryption Process

1. The user enters their data and passkey.
2. The passkey is hashed using the SHA-256 algorithm and a unique salt.
3. The hashed passkey is used to derive a Fernet key.
4. The data is encrypted using the Fernet key.
5. The encrypted data is stored in the system.

## Decryption Process

1. The user enters the encrypted data and the passkey.
2. The passkey is hashed using the SHA-256 algorithm and a unique salt.
3. The hashed passkey is used to derive a Fernet key.
4. The Fernet key is used to decrypt the data.
5. The decrypted data is displayed to the user.

This application also has a lockout feature to prevent brute force attacks. If a user enters the wrong passkey more than three times, they will be locked out for a minute.
