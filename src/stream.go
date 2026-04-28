package k9crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"

	"github.com/K9Crypt/k9crypt-go/src/constants"
)

const (
	ChunkSize = 64 * 1024
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

func defaultBatchSize() int {
	n := runtime.NumCPU() * 2
	if n < 1 {
		return 1
	}
	if n > 32 {
		return 32
	}
	return n
}

func (k *K9Crypt) EncryptFile(plaintext []byte, options *EncryptFileOptions) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("stream encryption failed")
	}

	if len(plaintext) > constants.MaxPlaintextSize {
		return "", errors.New("stream encryption failed")
	}

	if options == nil {
		options = &EncryptFileOptions{}
	}

	if options.CompressionLevel < 0 || options.CompressionLevel > 9 {
		options.CompressionLevel = constants.CompressionLevel
	}

	err := k.zlibCompressor.SetLevel(options.CompressionLevel)
	if err != nil {
		return "", errors.New("stream encryption failed")
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
			return "", errors.New("stream encryption failed")
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
		return "", errors.New("stream encryption failed")
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return "", errors.New("stream encryption failed")
	}

	var encryptedChunks [][]byte
	for _, chunk := range compressedChunks {
		encryptedChunk, err := k.aesEncryptor.MultiLayerEncrypt(chunk, keys)
		if err != nil {
			return "", errors.New("stream encryption failed")
		}
		encryptedChunks = append(encryptedChunks, encryptedChunk)
	}

	hash, err := k.generateHash(plaintext, salt)
	if err != nil {
		return "", errors.New("stream encryption failed")
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 131072))

	paddingSizeByte := make([]byte, 1)
	_, err = rand.Read(paddingSizeByte)
	if err != nil {
		return "", errors.New("stream encryption failed")
	}
	paddingSize := byte(4 + int(paddingSizeByte[0])%13)
	buffer.WriteByte(paddingSize)
	padding := make([]byte, int(paddingSize))
	_, err = rand.Read(padding)
	if err != nil {
		return "", errors.New("stream encryption failed")
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
		return nil, errors.New("stream decryption failed")
	}

	if options == nil {
		options = &DecryptFileOptions{}
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	if len(decodedData) > constants.MaxCiphertextSize {
		return nil, errors.New("stream decryption failed")
	}

	if len(decodedData) < constants.MinPayloadSize {
		return nil, errors.New("stream decryption failed")
	}

	reader := bytes.NewReader(decodedData)

	paddingSizeByte := make([]byte, 1)
	_, err = reader.Read(paddingSizeByte)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}
	paddingSize := int(paddingSizeByte[0])
	padding := make([]byte, paddingSize)
	_, err = reader.Read(padding)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	saltLenBytes := make([]byte, 4)
	_, err = reader.Read(saltLenBytes)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}
	saltLen := binary.LittleEndian.Uint32(saltLenBytes)

	salt := make([]byte, saltLen)
	_, err = reader.Read(salt)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	hashLenBytes := make([]byte, 4)
	_, err = reader.Read(hashLenBytes)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}
	hashLen := binary.LittleEndian.Uint32(hashLenBytes)

	hash := make([]byte, hashLen)
	_, err = reader.Read(hash)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	chunkCountBytes := make([]byte, 4)
	_, err = reader.Read(chunkCountBytes)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}
	chunkCount := binary.LittleEndian.Uint32(chunkCountBytes)

	var encryptedChunks [][]byte
	for i := uint32(0); i < chunkCount; i++ {
		chunkLenBytes := make([]byte, 4)
		_, err = reader.Read(chunkLenBytes)
		if err != nil {
			return nil, errors.New("stream decryption failed")
		}
		chunkLen := binary.LittleEndian.Uint32(chunkLenBytes)

		chunk := make([]byte, chunkLen)
		_, err = reader.Read(chunk)
		if err != nil {
			return nil, errors.New("stream decryption failed")
		}
		encryptedChunks = append(encryptedChunks, chunk)
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	var decryptedChunks [][]byte
	totalChunks := len(encryptedChunks)
	for i, chunk := range encryptedChunks {
		decryptedChunk, err := k.aesEncryptor.MultiLayerDecrypt(chunk, keys)
		if err != nil {
			return nil, errors.New("stream decryption failed")
		}

		decompressedChunk, err := k.decompressData(decryptedChunk)
		if err != nil {
			return nil, errors.New("stream decryption failed")
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
		return nil, errors.New("stream decryption failed")
	}

	return plaintext, nil
}

func (k *K9Crypt) EncryptMany(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	if len(dataArray) == 0 {
		return nil, errors.New("encryption failed")
	}

	if options == nil {
		options = &EncryptManyOptions{}
	}

	if options.BatchSize <= 0 {
		options.BatchSize = defaultBatchSize()
	}

	for i, data := range dataArray {
		if len(data) > constants.MaxPlaintextSize {
			return nil, errors.New("encryption failed")
		}
		_ = i
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
			return nil, errors.New("encryption failed")
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
	batchSize := options.BatchSize

	for i := 0; i < len(dataArray); i += batchSize {
		end := i + batchSize
		if end > len(dataArray) {
			end = len(dataArray)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var batchErr error

		for j := i; j < end; j++ {
			if dataArray[j] == "" {
				continue
			}

			wg.Add(1)
			go func(index int, plaintext string) {
				defer wg.Done()

				encrypted, err := k.Encrypt(plaintext)
				if err != nil {
					mu.Lock()
					batchErr = errors.New("encryption failed")
					mu.Unlock()
					return
				}
				results[index] = encrypted
			}(j, dataArray[j])
		}

		wg.Wait()

		if batchErr != nil {
			return nil, batchErr
		}
	}

	return results, nil
}

func (k *K9Crypt) DecryptMany(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	if len(ciphertextArray) == 0 {
		return nil, errors.New("decryption failed")
	}

	if options == nil {
		options = &DecryptManyOptions{}
	}

	if options.BatchSize <= 0 {
		options.BatchSize = defaultBatchSize()
	}

	for i, data := range ciphertextArray {
		if data == "" {
			continue
		}
		if len(data) > constants.MaxCiphertextSize {
			return nil, errors.New("decryption failed")
		}
		if len(data) < constants.MinPayloadSize {
			if options.SkipInvalid {
				continue
			}
			return nil, errors.New("decryption failed")
		}
		_ = i
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
			return nil, errors.New("decryption failed")
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
	batchSize := options.BatchSize

	for i := 0; i < len(ciphertextArray); i += batchSize {
		end := i + batchSize
		if end > len(ciphertextArray) {
			end = len(ciphertextArray)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var batchErr error

		for j := i; j < end; j++ {
			if ciphertextArray[j] == "" {
				continue
			}

			wg.Add(1)
			go func(index int, encrypted string) {
				defer wg.Done()

				decrypted, err := k.Decrypt(encrypted)
				if err != nil {
					if options.SkipInvalid {
						results[index] = ""
						return
					}
					mu.Lock()
					batchErr = errors.New("decryption failed")
					mu.Unlock()
					return
				}
				results[index] = decrypted
			}(j, ciphertextArray[j])
		}

		wg.Wait()

		if batchErr != nil {
			return nil, batchErr
		}
	}

	return results, nil
}
