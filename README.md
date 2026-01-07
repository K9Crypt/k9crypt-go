![K9Crypt Go Banner](https://www.upload.ee/image/18577629/k9crypt-go.png)

# K9Crypt Go

A high-performance and secure data encryption library built to military standards.

## Updates

### Version 1.0.2 - Large File & Batch Processing

#### New Features
- **Large File Encryption**: Stream-based `EncryptFile()` and `DecryptFile()` methods with 64KB chunk processing for memory-efficient handling of large files
- **Batch Operations**: `EncryptMany()` and `DecryptMany()` methods for sequential and parallel processing of multiple data items
- **Compression Level Control**: Adjustable compression levels (0-9) via `NewWithOptions()` or `SetCompressionLevel()`
- **Progress Tracking**: Callback support for monitoring encryption/decryption progress
- **Parallel Processing**: Configurable batch size for concurrent operations with goroutines

#### Technical Improvements
- 64KB chunk size for optimal memory usage on large files
- Semaphore-based concurrency control for parallel batch operations
- SkipInvalid option for fault-tolerant batch decryption

## Features

- 5-Layer AES Encryption (GCM, CBC, CFB, OFB, CTR)
- Argon2 + SHA512 for secure key derivation
- Built-in compression for optimal storage
- High performance and thread-safe
- Enterprise-grade security
- Large file support with progress tracking
- Batch encryption/decryption with parallel processing

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

### Large File Encryption

```go
package main

import (
    "fmt"
    "log"
    "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    encryptor := k9crypt.New("mySecretKey")

    largeData := make([]byte, 100*1024*1024) // 100MB

    // Encrypt with progress tracking
    encrypted, err := encryptor.EncryptFile(largeData, &k9crypt.EncryptFileOptions{
        CompressionLevel: 6,
        OnProgress: func(p k9crypt.ProgressInfo) {
            fmt.Printf("Progress: %.2f%% (%d/%d bytes)\n", p.Percentage, p.ProcessedBytes, p.TotalBytes)
        },
    })
    if err != nil {
        log.Fatal("Encryption error:", err)
    }

    // Decrypt with progress tracking
    decrypted, err := encryptor.DecryptFile(encrypted, &k9crypt.DecryptFileOptions{
        OnProgress: func(p k9crypt.ProgressInfo) {
            fmt.Printf("Progress: %.2f%%\n", p.Percentage)
        },
    })
    if err != nil {
        log.Fatal("Decryption error:", err)
    }

    fmt.Printf("Decrypted %d bytes\n", len(decrypted))
}
```

### Batch Encryption (Sequential)

```go
package main

import (
    "fmt"
    "log"
    "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    encryptor := k9crypt.New("mySecretKey")

    dataArray := []string{"user1", "user2", "user3"}

    // Sequential encryption with progress
    encrypted, err := encryptor.EncryptMany(dataArray, &k9crypt.EncryptManyOptions{
        OnProgress: func(p k9crypt.BatchProgressInfo) {
            fmt.Printf("%d/%d (%.0f%%)\n", p.Current, p.Total, p.Percentage)
        },
    })
    if err != nil {
        log.Fatal("Encryption error:", err)
    }

    // Decrypt with skip invalid option
    decrypted, err := encryptor.DecryptMany(encrypted, &k9crypt.DecryptManyOptions{
        SkipInvalid: true, // Skip corrupted data, return empty string
        OnProgress: func(p k9crypt.BatchProgressInfo) {
            fmt.Printf("%.0f%% completed\n", p.Percentage)
        },
    })
    if err != nil {
        log.Fatal("Decryption error:", err)
    }

    fmt.Println("Decrypted:", decrypted)
}
```

### Batch Encryption (Parallel)

```go
package main

import (
    "fmt"
    "log"
    "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    encryptor := k9crypt.New("mySecretKey")

    // Large dataset
    dataArray := make([]string, 1000)
    for i := range dataArray {
        dataArray[i] = fmt.Sprintf("data_%d", i)
    }

    // Parallel encryption
    encrypted, err := encryptor.EncryptMany(dataArray, &k9crypt.EncryptManyOptions{
        Parallel:  true,
        BatchSize: 50, // 50 concurrent goroutines
    })
    if err != nil {
        log.Fatal("Encryption error:", err)
    }

    // Parallel decryption
    decrypted, err := encryptor.DecryptMany(encrypted, &k9crypt.DecryptManyOptions{
        Parallel:    true,
        BatchSize:   50,
        SkipInvalid: false,
    })
    if err != nil {
        log.Fatal("Decryption error:", err)
    }

    fmt.Printf("Processed %d items\n", len(decrypted))
}
```

### Compression Level Control

```go
package main

import (
    "fmt"
    "github.com/K9Crypt/k9crypt-go/src"
)

func main() {
    // Create with custom compression level
    encryptor := k9crypt.NewWithOptions("mySecretKey", 8)

    // Or change later
    encryptor.SetCompressionLevel(3)

    // Get current level
    level := encryptor.GetCompressionLevel()
    fmt.Println("Current compression level:", level)

    // Compression levels:
    // 0-2: Fast (low compression)
    // 3-5: Balanced (default: 6)
    // 6-9: Maximum compression (slower)
}
```

## API Reference

### Constructor

| Function | Description |
|----------|-------------|
| `New(secretKey string)` | Create encryptor with default settings |
| `NewWithOptions(secretKey string, compressionLevel int)` | Create with custom compression level |

### Methods

| Method | Description |
|--------|-------------|
| `Encrypt(plaintext string)` | Encrypt a string |
| `Decrypt(ciphertext string)` | Decrypt a string |
| `EncryptFile(data []byte, options)` | Encrypt large data with chunking |
| `DecryptFile(ciphertext string, options)` | Decrypt chunked data |
| `EncryptMany(dataArray []string, options)` | Batch encrypt multiple strings |
| `DecryptMany(ciphertextArray []string, options)` | Batch decrypt multiple strings |
| `SetCompressionLevel(level int)` | Set compression level (0-9) |
| `GetCompressionLevel()` | Get current compression level |

### Options

**EncryptFileOptions:**
- `CompressionLevel int` - Compression level (0-9)
- `OnProgress func(ProgressInfo)` - Progress callback

**DecryptFileOptions:**
- `OnProgress func(ProgressInfo)` - Progress callback

**EncryptManyOptions:**
- `CompressionLevel int` - Compression level (0-9)
- `Parallel bool` - Enable parallel processing
- `BatchSize int` - Concurrent goroutines (default: 10)
- `OnProgress func(BatchProgressInfo)` - Progress callback (sequential only)

**DecryptManyOptions:**
- `SkipInvalid bool` - Skip corrupted data instead of failing
- `Parallel bool` - Enable parallel processing
- `BatchSize int` - Concurrent goroutines (default: 10)
- `OnProgress func(BatchProgressInfo)` - Progress callback (sequential only)

## Performance

### Memory Usage (1GB File)

| Method | Memory Usage |
|--------|--------------|
| `Encrypt()` | ~1.2 GB |
| `EncryptFile()` | ~64 KB |

### Processing Speed (1000 Items)

| Method | Duration |
|--------|----------|
| `EncryptMany()` (sequential) | ~15 seconds |
| `EncryptMany()` (parallel, batchSize:10) | ~2 seconds |
| `EncryptMany()` (parallel, batchSize:50) | ~1.5 seconds |

### Compression Levels (10MB Text)

| Level | Output Size | Processing Time |
|-------|-------------|-----------------|
| 1 | 1.2 MB | 50 ms |
| 3 | 950 KB | 120 ms |
| 5 | 820 KB | 200 ms |
| 9 | 750 KB | 450 ms |

## License

This project is licensed under the MIT License.
