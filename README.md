![K9Crypt Go Banner](https://www.upload.ee/image/18577629/k9crypt-go.png)

# K9Crypt Go

K9Crypt Go is a production-focused encryption module with a versioned payload format, authenticated metadata, bounded batch processing, and safe defaults for low-latency application encryption.

## Installation

```bash
go get github.com/K9Crypt/k9crypt-go
```

## Usage

### Basic Encryption

```go
package main

import (
    "fmt"
    "log"

    k9crypt "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    encryptor, err := k9crypt.New("VeryLongSecretKey!@#1234567890")
    if err != nil {
        log.Fatal(err)
    }

    encrypted, err := encryptor.Encrypt("Hello, World!")
    if err != nil {
        log.Fatal(err)
    }

    decrypted, err := encryptor.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(decrypted)
}
```

### Generated Key

```go
encryptor, err := k9crypt.NewGenerated()
if err != nil {
    log.Fatal(err)
}

generatedKey := encryptor.GetGenerated()
```

### Binary Payloads

```go
data := []byte{0x00, 0xff, 0x10, 0x80}

encrypted, err := encryptor.EncryptBytes(data, nil)
if err != nil {
    log.Fatal(err)
}

decrypted, err := encryptor.DecryptBytes(encrypted, nil)
if err != nil {
    log.Fatal(err)
}
```

### Time-Scoped Payloads And Freshness

```go
issuedAt := int64(1700000000)
encrypted, err := encryptor.EncryptWithOptions("short-lived", &k9crypt.EncryptOptions{
    IssuedAtUnix:    &issuedAt,
    TimeStepSeconds: 300,
})
if err != nil {
    log.Fatal(err)
}

maxAge := int64(300)
now := int64(1700000100)
decrypted, err := encryptor.DecryptWithOptions(encrypted, &k9crypt.DecryptOptions{
    MaxAgeSeconds:           &maxAge,
    AllowedClockSkewSeconds: 30,
    NowUnixSeconds:          &now,
})
if err != nil {
    log.Fatal(err)
}

fmt.Println(decrypted)
```

### Compression Override

```go
level := 6
encrypted, err := encryptor.EncryptWithOptions("compressible payload", &k9crypt.EncryptOptions{
    CompressionLevel: &level,
})
```

### Buffered File Encryption

```go
data := make([]byte, 1024*1024)

encrypted, err := encryptor.EncryptFile(data, &k9crypt.EncryptFileOptions{
    CompressionLevel: 0,
    OnProgress: func(p k9crypt.ProgressInfo) {
        fmt.Printf("%.0f%%\n", p.Percentage)
    },
})
if err != nil {
    log.Fatal(err)
}

decrypted, err := encryptor.DecryptFile(encrypted, nil)
if err != nil {
    log.Fatal(err)
}

fmt.Println(len(decrypted))
```

### Batch Encryption

```go
items := []string{"user1", "user2", "user3"}

encrypted, err := encryptor.EncryptMany(items, &k9crypt.EncryptManyOptions{
    Parallel:  true,
    BatchSize: 2,
})
if err != nil {
    log.Fatal(err)
}

decrypted, err := encryptor.DecryptMany(encrypted, &k9crypt.DecryptManyOptions{
    Parallel:    true,
    BatchSize:   2,
    SkipInvalid: false,
})
if err != nil {
    log.Fatal(err)
}

fmt.Println(decrypted)
```

### Strict Compatibility Policy

```go
allowLegacy := false
plaintext, err := encryptor.DecryptWithOptions(ciphertext, &k9crypt.DecryptOptions{
    AllowLegacyPayloads: &allowLegacy,
})
```

## API Reference

### Constructors

| Function                                                                         | Description                                                                                             |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `New(secretKey string) (*K9Crypt, error)`                                        | Creates an encryptor from a non-empty string secret.                                                    |
| `NewGenerated() (*K9Crypt, error)`                                               | Creates an encryptor with a 50-byte random secret.                                                      |
| `NewWithKey(secretKey []byte) (*K9Crypt, error)`                                 | Creates an encryptor from a cloned byte-slice secret; `nil` generates a key, empty slices are rejected. |
| `NewWithOptions(secretKey string, compressionLevel int) (*K9Crypt, error)`       | Creates a string-key encryptor with a default compression level.                                        |
| `NewWithKeyAndOptions(secretKey []byte, compressionLevel int) (*K9Crypt, error)` | Creates a byte-key encryptor with a default compression level.                                          |
| `NewGeneratedWithOptions(compressionLevel int) (*K9Crypt, error)`                | Creates a generated-key encryptor with a default compression level.                                     |

### Methods

| Method                                                               | Description                                                                   |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `Encrypt(plaintext string)`                                          | Encrypts a string with default options.                                       |
| `EncryptWithOptions(plaintext string, options *EncryptOptions)`      | Encrypts a string with time/compression options.                              |
| `EncryptBytes(plaintext []byte, options *EncryptOptions)`            | Encrypts binary data and marks the payload as binary.                         |
| `Decrypt(ciphertext string)`                                         | Decrypts a string payload.                                                    |
| `DecryptWithOptions(ciphertext string, options *DecryptOptions)`     | Decrypts with freshness and compatibility policy checks.                      |
| `DecryptBytes(ciphertext string, options *DecryptOptions)`           | Decrypts and returns raw bytes.                                               |
| `EncryptFile(data []byte, options *EncryptFileOptions)`              | Encrypts buffered file data up to 16 MB.                                      |
| `DecryptFile(ciphertext string, options *DecryptFileOptions)`        | Decrypts buffered file data up to 16 MB.                                      |
| `EncryptMany(dataArray []string, options *EncryptManyOptions)`       | Batch encrypts strings.                                                       |
| `DecryptMany(ciphertextArray []string, options *DecryptManyOptions)` | Batch decrypts strings.                                                       |
| `SetCompressionLevel(level int)`                                     | Sets default compression level `0-9`.                                         |
| `GetCompressionLevel()`                                              | Returns current default compression level.                                    |
| `GetGenerated()`                                                     | Returns a copy of the generated secret, or `nil` for caller-provided secrets. |

### Options

**EncryptOptions**

- `CompressionLevel *int` - optional per-call compression level; `0` means raw mode.
- `TimeStepSeconds uint32` - optional time bucket size, default `300`, maximum `86400`.
- `IssuedAtUnix *int64` - optional authenticated issue time.

**DecryptOptions**

- `MaxAgeSeconds *int64` - optional freshness limit.
- `AllowedClockSkewSeconds int64` - optional clock skew allowance.
- `NowUnixSeconds *int64` - optional deterministic validation time.
- `AllowLegacyPayloads *bool` - default `true`; set to `false` to reject pre-v4 payloads.

**EncryptFileOptions / EncryptManyOptions** also expose compression, time metadata, progress, and parallel batch controls where applicable.

**DecryptFileOptions / DecryptManyOptions** also expose freshness, compatibility, progress, `SkipInvalid`, and parallel batch controls where applicable.

## License

This project is licensed under the MIT License.
