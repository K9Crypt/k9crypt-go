![K9Crypt Go Banner](https://www.upload.ee/image/18577629/k9crypt-go.png)

# K9Crypt Go

A high-performance and secure data encryption library built to military standards.

## Features

- 5-Layer AES Encryption (GCM, CBC, CFB, OFB, CTR)
- Argon2 + SHA512 for secure key derivation
- Built-in compression for optimal storage
- Full Unicode and emoji support
- High performance and thread-safe
- Enterprise-grade security

## Installation

```bash
go get github.com/K9Crypt/k9crypt-go
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    // Create encryptor with secret key
    secretKey := "VeryLongSecretKey!@#1234567890"
    encryptor := k9crypt.New(secretKey)

    // Or auto-generate a secure key
    // encryptor := k9crypt.New("")

    plaintext := "Hello, World!"

    // Encrypt
    encrypted, err := encryptor.Encrypt(plaintext)
    if err != nil {
        log.Fatal("Encryption error:", err)
    }
    fmt.Println("Encrypted:", encrypted)

    // Decrypt
    decrypted, err := encryptor.Decrypt(encrypted)
    if err != nil {
        log.Fatal("Decryption error:", err)
    }
    fmt.Println("Decrypted:", decrypted)
}
```

## License

This project is licensed under the MIT License.
