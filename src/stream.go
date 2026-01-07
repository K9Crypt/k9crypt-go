package k9crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	ChunkSize        = 64 * 1024
	DefaultBatchSize = 10
)

type ProgressInfo struct {
	ProcessedBytes int64
	TotalBytes     int64
	Percentage     float64
}

type BatchProgressInfo struct {
	Current    int
	Total      int
	Percentage float64
}

type EncryptFileOptions struct {
	CompressionLevel int
	OnProgress       func(ProgressInfo)
}

type DecryptFileOptions struct {
	OnProgress func(ProgressInfo)
}

type EncryptManyOptions struct {
	CompressionLevel int
	Parallel         bool
	BatchSize        int
	OnProgress       func(BatchProgressInfo)
}

type DecryptManyOptions struct {
	SkipInvalid bool
	Parallel    bool
	BatchSize   int
	OnProgress  func(BatchProgressInfo)
}

func (k *K9Crypt) EncryptFile(plaintext []byte, options *EncryptFileOptions) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("input data cannot be empty")
	}

	if options == nil {
		options = &EncryptFileOptions{}
	}

	if options.CompressionLevel < 0 || options.CompressionLevel > 9 {
		options.CompressionLevel = 6
	}

	err := k.zlibCompressor.SetLevel(options.CompressionLevel)
	if err != nil {
		return "", fmt.Errorf("failed to set compression level: %w", err)
	}

	totalBytes := int64(len(plaintext))
	processedBytes := int64(0)

	var compressedChunks [][]byte
	for i := 0; i < len(plaintext); i += ChunkSize {
		end := i + ChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		chunk := plaintext[i:end]
		compressedChunk, err := k.compressData(chunk)
		if err != nil {
			return "", fmt.Errorf("compression failed at chunk %d: %w", i/ChunkSize, err)
		}

		compressedChunks = append(compressedChunks, compressedChunk)
		processedBytes += int64(len(chunk))

		if options.OnProgress != nil {
			options.OnProgress(ProgressInfo{
				ProcessedBytes: processedBytes,
				TotalBytes:     totalBytes,
				Percentage:     float64(processedBytes) / float64(totalBytes) * 100,
			})
		}
	}

	salt, err := k.argon2Hasher.GenerateSalt()
	if err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	var encryptedChunks [][]byte
	for i, chunk := range compressedChunks {
		encryptedChunk, err := k.aesEncryptor.MultiLayerEncrypt(chunk, keys)
		if err != nil {
			return "", fmt.Errorf("encryption failed at chunk %d: %w", i, err)
		}
		encryptedChunks = append(encryptedChunks, encryptedChunk)
	}

	hash, err := k.generateHash(plaintext, salt)
	if err != nil {
		return "", fmt.Errorf("hash generation failed: %w", err)
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 131072))

	paddingSizeByte := make([]byte, 1)
	_, err = rand.Read(paddingSizeByte)
	if err != nil {
		return "", fmt.Errorf("failed to generate padding size: %w", err)
	}
	paddingSize := byte(4 + int(paddingSizeByte[0])%13)
	buffer.WriteByte(paddingSize)
	padding := make([]byte, int(paddingSize))
	_, err = rand.Read(padding)
	if err != nil {
		return "", fmt.Errorf("failed to generate padding: %w", err)
	}
	buffer.Write(padding)

	saltLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(saltLen, uint32(len(salt)))
	buffer.Write(saltLen)
	buffer.Write(salt)

	hashLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(hashLen, uint32(len(hash)))
	buffer.Write(hashLen)
	buffer.Write(hash)

	chunkCount := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkCount, uint32(len(encryptedChunks)))
	buffer.Write(chunkCount)

	for _, chunk := range encryptedChunks {
		chunkLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(chunkLen, uint32(len(chunk)))
		buffer.Write(chunkLen)
		buffer.Write(chunk)
	}

	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func (k *K9Crypt) DecryptFile(encryptedData string, options *DecryptFileOptions) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, fmt.Errorf("encrypted data cannot be empty")
	}

	if options == nil {
		options = &DecryptFileOptions{}
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 data: %w", err)
	}

	if len(decodedData) < 17 {
		return nil, fmt.Errorf("invalid encrypted data format")
	}

	reader := bytes.NewReader(decodedData)

	paddingSizeByte := make([]byte, 1)
	_, err = reader.Read(paddingSizeByte)
	if err != nil {
		return nil, fmt.Errorf("failed to read padding size: %w", err)
	}
	paddingSize := int(paddingSizeByte[0])
	padding := make([]byte, paddingSize)
	_, err = reader.Read(padding)
	if err != nil {
		return nil, fmt.Errorf("failed to read padding: %w", err)
	}

	saltLenBytes := make([]byte, 4)
	_, err = reader.Read(saltLenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt length: %w", err)
	}
	saltLen := binary.LittleEndian.Uint32(saltLenBytes)

	salt := make([]byte, saltLen)
	_, err = reader.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	hashLenBytes := make([]byte, 4)
	_, err = reader.Read(hashLenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read hash length: %w", err)
	}
	hashLen := binary.LittleEndian.Uint32(hashLenBytes)

	hash := make([]byte, hashLen)
	_, err = reader.Read(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to read hash: %w", err)
	}

	chunkCountBytes := make([]byte, 4)
	_, err = reader.Read(chunkCountBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk count: %w", err)
	}
	chunkCount := binary.LittleEndian.Uint32(chunkCountBytes)

	var encryptedChunks [][]byte
	for i := uint32(0); i < chunkCount; i++ {
		chunkLenBytes := make([]byte, 4)
		_, err = reader.Read(chunkLenBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk length at chunk %d: %w", i, err)
		}
		chunkLen := binary.LittleEndian.Uint32(chunkLenBytes)

		chunk := make([]byte, chunkLen)
		_, err = reader.Read(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk at chunk %d: %w", i, err)
		}
		encryptedChunks = append(encryptedChunks, chunk)
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	var decryptedChunks [][]byte
	totalChunks := len(encryptedChunks)
	for i, chunk := range encryptedChunks {
		decryptedChunk, err := k.aesEncryptor.MultiLayerDecrypt(chunk, keys)
		if err != nil {
			return nil, fmt.Errorf("decryption failed at chunk %d: %w", i, err)
		}

		decompressedChunk, err := k.decompressData(decryptedChunk)
		if err != nil {
			return nil, fmt.Errorf("decompression failed at chunk %d: %w", i, err)
		}

		decryptedChunks = append(decryptedChunks, decompressedChunk)

		if options.OnProgress != nil {
			options.OnProgress(ProgressInfo{
				ProcessedBytes: int64((i + 1) * ChunkSize),
				TotalBytes:     int64(totalChunks * ChunkSize),
				Percentage:     float64(i+1) / float64(totalChunks) * 100,
			})
		}
	}

	result := bytes.NewBuffer(make([]byte, 0, len(decryptedChunks)*ChunkSize))
	for _, chunk := range decryptedChunks {
		result.Write(chunk)
	}

	plaintext := result.Bytes()

	if !k.verifyHash(plaintext, salt, hash) {
		return nil, fmt.Errorf("hash verification failed: data integrity compromised")
	}

	return plaintext, nil
}

func (k *K9Crypt) EncryptMany(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	if len(dataArray) == 0 {
		return nil, fmt.Errorf("data array cannot be empty")
	}

	if options == nil {
		options = &EncryptManyOptions{}
	}

	if options.BatchSize <= 0 {
		options.BatchSize = DefaultBatchSize
	}

	if options.Parallel {
		return k.encryptManyParallel(dataArray, options)
	}

	return k.encryptManySequential(dataArray, options)
}

func (k *K9Crypt) encryptManySequential(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	results := make([]string, len(dataArray))
	total := len(dataArray)

	for i, data := range dataArray {
		if data == "" {
			results[i] = ""
			continue
		}

		encrypted, err := k.Encrypt(data)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at index %d: %w", i, err)
		}

		results[i] = encrypted

		if options.OnProgress != nil {
			options.OnProgress(BatchProgressInfo{
				Current:    i + 1,
				Total:      total,
				Percentage: float64(i+1) / float64(total) * 100,
			})
		}
	}

	return results, nil
}

func (k *K9Crypt) encryptManyParallel(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	results := make([]string, len(dataArray))
	errors := make([]error, len(dataArray))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, options.BatchSize)

	for i, data := range dataArray {
		if data == "" {
			results[i] = ""
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(index int, plaintext string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			encrypted, err := k.Encrypt(plaintext)
			if err != nil {
				errors[index] = err
				return
			}
			results[index] = encrypted
		}(i, data)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("encryption failed at index %d: %w", i, err)
		}
	}

	return results, nil
}

func (k *K9Crypt) DecryptMany(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	if len(ciphertextArray) == 0 {
		return nil, fmt.Errorf("ciphertext array cannot be empty")
	}

	if options == nil {
		options = &DecryptManyOptions{}
	}

	if options.BatchSize <= 0 {
		options.BatchSize = DefaultBatchSize
	}

	if options.Parallel {
		return k.decryptManyParallel(ciphertextArray, options)
	}

	return k.decryptManySequential(ciphertextArray, options)
}

func (k *K9Crypt) decryptManySequential(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	results := make([]string, len(ciphertextArray))
	total := len(ciphertextArray)

	for i, ciphertext := range ciphertextArray {
		if ciphertext == "" {
			results[i] = ""
			continue
		}

		decrypted, err := k.Decrypt(ciphertext)
		if err != nil {
			if options.SkipInvalid {
				results[i] = ""
				continue
			}
			return nil, fmt.Errorf("decryption failed at index %d: %w", i, err)
		}

		results[i] = decrypted

		if options.OnProgress != nil {
			options.OnProgress(BatchProgressInfo{
				Current:    i + 1,
				Total:      total,
				Percentage: float64(i+1) / float64(total) * 100,
			})
		}
	}

	return results, nil
}

func (k *K9Crypt) decryptManyParallel(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	results := make([]string, len(ciphertextArray))
	errors := make([]error, len(ciphertextArray))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, options.BatchSize)

	for i, ciphertext := range ciphertextArray {
		if ciphertext == "" {
			results[i] = ""
			continue
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(index int, encrypted string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			decrypted, err := k.Decrypt(encrypted)
			if err != nil {
				if options.SkipInvalid {
					results[index] = ""
					return
				}
				errors[index] = err
				return
			}
			results[index] = decrypted
		}(i, ciphertext)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("decryption failed at index %d: %w", i, err)
		}
	}

	return results, nil
}
