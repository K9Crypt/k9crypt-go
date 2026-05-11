package k9crypt

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/K9Crypt/k9crypt-go/src/constants"
)

const (
	ChunkSize            = 64 * 1024
	defaultBatchSize     = 1
	maxParallelBatchSize = 2
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
	TimeStepSeconds  uint32
	IssuedAtUnix     *int64
	OnProgress       func(ProgressInfo)
}

type DecryptFileOptions struct {
	MaxAgeSeconds           *int64
	AllowedClockSkewSeconds int64
	NowUnixSeconds          *int64
	AllowLegacyPayloads     *bool
	OnProgress              func(ProgressInfo)
}

type EncryptManyOptions struct {
	CompressionLevel int
	TimeStepSeconds  uint32
	IssuedAtUnix     *int64
	Parallel         bool
	BatchSize        int
	OnProgress       func(BatchProgressInfo)
}

type DecryptManyOptions struct {
	MaxAgeSeconds           *int64
	AllowedClockSkewSeconds int64
	NowUnixSeconds          *int64
	AllowLegacyPayloads     *bool
	SkipInvalid             bool
	Parallel                bool
	BatchSize               int
	OnProgress              func(BatchProgressInfo)
}

func (k *K9Crypt) EncryptFile(plaintext []byte, options *EncryptFileOptions) (string, error) {
	input := plaintext
	if input == nil {
		input = []byte{}
	}

	if len(input) > constants.MaxBufferedFileSize {
		return "", errors.New("stream encryption failed")
	}

	encrypted, err := k.EncryptBytes(input, encryptFileOptions(options))
	if err != nil {
		return "", errors.New("stream encryption failed")
	}

	if options != nil && options.OnProgress != nil {
		reportFileProgress(options.OnProgress, int64(len(input)), int64(len(input)))
	}

	return encrypted, nil
}

func (k *K9Crypt) DecryptFile(encryptedData string, options *DecryptFileOptions) ([]byte, error) {
	decodedData, err := decodePayloadString(encryptedData)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	decryptOptions := decryptFileOptions(options)
	if hasVersionedPayload(decodedData) {
		plaintext, err := k.decryptDecodedBytes(decodedData, decryptOptions)
		if err != nil {
			return nil, errors.New("stream decryption failed")
		}

		if len(plaintext) > constants.MaxBufferedFileSize {
			return nil, errors.New("stream decryption failed")
		}

		if options != nil && options.OnProgress != nil {
			reportFileProgress(options.OnProgress, int64(len(plaintext)), int64(len(plaintext)))
		}

		return plaintext, nil
	}

	if !legacyPayloadsAllowed(decryptOptions) {
		return nil, errors.New("stream decryption failed")
	}

	if looksLikeLengthPrefixedLegacyPayload(decodedData) {
		return k.decryptLegacyFilePayload(decodedData, options)
	}

	plaintext, err := k.decryptLegacyV1Payload(decodedData)
	if err == nil {
		if len(plaintext) > constants.MaxBufferedFileSize {
			return nil, errors.New("stream decryption failed")
		}

		if options != nil && options.OnProgress != nil {
			reportFileProgress(options.OnProgress, int64(len(plaintext)), int64(len(plaintext)))
		}

		return plaintext, nil
	}

	return k.decryptLegacyFilePayload(decodedData, options)
}

func (k *K9Crypt) EncryptMany(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	if len(dataArray) == 0 {
		return []string{}, nil
	}

	if options != nil && options.Parallel {
		return k.encryptManyParallel(dataArray, options)
	}

	return k.encryptManySequential(dataArray, options)
}

func (k *K9Crypt) DecryptMany(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	if len(ciphertextArray) == 0 {
		return []string{}, nil
	}

	if options != nil && options.Parallel {
		return k.decryptManyParallel(ciphertextArray, options)
	}

	return k.decryptManySequential(ciphertextArray, options)
}

func (k *K9Crypt) encryptManySequential(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	results := make([]string, len(dataArray))
	encryptOptions := encryptManyOptions(options)
	total := len(dataArray)

	for i, data := range dataArray {
		encrypted, err := k.EncryptWithOptions(data, encryptOptions)
		if err != nil {
			return nil, errors.New("encryption failed")
		}

		results[i] = encrypted
		reportBatchProgress(optionEncryptProgress(options), i+1, total)
	}

	return results, nil
}

func (k *K9Crypt) encryptManyParallel(dataArray []string, options *EncryptManyOptions) ([]string, error) {
	results := make([]string, len(dataArray))
	batchSize := resolveBatchSize(0)
	if options != nil {
		batchSize = resolveBatchSize(options.BatchSize)
	}

	for i := 0; i < len(dataArray); i += batchSize {
		end := i + batchSize
		if end > len(dataArray) {
			end = len(dataArray)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var batchErr error

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(index int, plaintext string) {
				defer wg.Done()

				encrypted, err := k.EncryptWithOptions(plaintext, encryptManyOptions(options))
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

		reportBatchProgress(optionEncryptProgress(options), end, len(dataArray))
	}

	return results, nil
}

func (k *K9Crypt) decryptManySequential(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	results := make([]string, len(ciphertextArray))
	decryptOptions := decryptManyOptions(options)
	total := len(ciphertextArray)

	for i, ciphertext := range ciphertextArray {
		decrypted, err := k.DecryptWithOptions(ciphertext, decryptOptions)
		if err != nil {
			if options != nil && options.SkipInvalid {
				results[i] = ""
				reportBatchProgress(optionDecryptProgress(options), i+1, total)
				continue
			}
			return nil, errors.New("decryption failed")
		}

		results[i] = decrypted
		reportBatchProgress(optionDecryptProgress(options), i+1, total)
	}

	return results, nil
}

func (k *K9Crypt) decryptManyParallel(ciphertextArray []string, options *DecryptManyOptions) ([]string, error) {
	results := make([]string, len(ciphertextArray))
	batchSize := resolveBatchSize(0)
	if options != nil {
		batchSize = resolveBatchSize(options.BatchSize)
	}

	for i := 0; i < len(ciphertextArray); i += batchSize {
		end := i + batchSize
		if end > len(ciphertextArray) {
			end = len(ciphertextArray)
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var batchErr error

		for j := i; j < end; j++ {
			wg.Add(1)
			go func(index int, encrypted string) {
				defer wg.Done()

				decrypted, err := k.DecryptWithOptions(encrypted, decryptManyOptions(options))
				if err != nil {
					if options != nil && options.SkipInvalid {
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

		reportBatchProgress(optionDecryptProgress(options), end, len(ciphertextArray))
	}

	return results, nil
}

func (k *K9Crypt) decryptLegacyFilePayload(decodedData []byte, options *DecryptFileOptions) ([]byte, error) {
	if len(decodedData) < constants.LegacyMinPayloadSize+4 {
		return nil, errors.New("stream decryption failed")
	}

	reader := bytes.NewReader(decodedData)
	paddingSizeByte, err := reader.ReadByte()
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	paddingSize := int(paddingSizeByte)
	if paddingSize < 4 || paddingSize > 16 || reader.Len() < paddingSize+4 {
		return nil, errors.New("stream decryption failed")
	}

	_, err = reader.Seek(int64(paddingSize), io.SeekCurrent)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	saltLen, err := readUint32Little(reader)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	if saltLen != constants.Argon2SaltSize || reader.Len() < int(saltLen)+4 {
		return nil, errors.New("stream decryption failed")
	}

	salt := make([]byte, saltLen)
	_, err = io.ReadFull(reader, salt)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	hashLen, err := readUint32Little(reader)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	if hashLen != sha512.Size || reader.Len() < int(hashLen)+4 {
		return nil, errors.New("stream decryption failed")
	}

	hash := make([]byte, hashLen)
	_, err = io.ReadFull(reader, hash)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	chunkCountBytes := make([]byte, 4)
	_, err = io.ReadFull(reader, chunkCountBytes)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}
	chunkCount := binary.LittleEndian.Uint32(chunkCountBytes)
	maxChunks := uint32(constants.MaxBufferedFileSize/ChunkSize + 1)
	if chunkCount == 0 || chunkCount > maxChunks {
		return nil, errors.New("stream decryption failed")
	}

	encryptedChunks := make([][]byte, 0, chunkCount)
	for i := uint32(0); i < chunkCount; i++ {
		chunkLen, readErr := readUint32Little(reader)
		if readErr != nil {
			return nil, errors.New("stream decryption failed")
		}

		if chunkLen == 0 || int(chunkLen) > reader.Len() {
			return nil, errors.New("stream decryption failed")
		}

		chunk := make([]byte, chunkLen)
		_, readErr = io.ReadFull(reader, chunk)
		if readErr != nil {
			return nil, errors.New("stream decryption failed")
		}
		encryptedChunks = append(encryptedChunks, chunk)
	}

	if reader.Len() != 0 {
		return nil, errors.New("stream decryption failed")
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return nil, errors.New("stream decryption failed")
	}

	result := bytes.NewBuffer(make([]byte, 0, len(encryptedChunks)*ChunkSize))
	for i, chunk := range encryptedChunks {
		decryptedChunk, decryptErr := k.aesEncryptor.MultiLayerDecrypt(chunk, keys)
		if decryptErr != nil {
			return nil, errors.New("stream decryption failed")
		}

		decompressedChunk, decompressErr := k.decompressData(decryptedChunk)
		if decompressErr != nil {
			return nil, errors.New("stream decryption failed")
		}

		if result.Len()+len(decompressedChunk) > constants.MaxBufferedFileSize {
			return nil, errors.New("stream decryption failed")
		}

		result.Write(decompressedChunk)
		reportFileProgress(optionFileProgress(options), int64(i+1), int64(len(encryptedChunks)))
	}

	plaintext := result.Bytes()
	if !k.verifyHash(plaintext, salt, hash) {
		return nil, errors.New("stream decryption failed")
	}

	return plaintext, nil
}

func encryptFileOptions(options *EncryptFileOptions) *EncryptOptions {
	if options == nil {
		return nil
	}

	level := options.CompressionLevel
	return &EncryptOptions{
		CompressionLevel: &level,
		TimeStepSeconds:  options.TimeStepSeconds,
		IssuedAtUnix:     options.IssuedAtUnix,
	}
}

func decryptFileOptions(options *DecryptFileOptions) *DecryptOptions {
	if options == nil {
		return nil
	}

	return &DecryptOptions{
		MaxAgeSeconds:           options.MaxAgeSeconds,
		AllowedClockSkewSeconds: options.AllowedClockSkewSeconds,
		NowUnixSeconds:          options.NowUnixSeconds,
		AllowLegacyPayloads:     options.AllowLegacyPayloads,
	}
}

func encryptManyOptions(options *EncryptManyOptions) *EncryptOptions {
	if options == nil {
		return nil
	}

	level := options.CompressionLevel
	return &EncryptOptions{
		CompressionLevel: &level,
		TimeStepSeconds:  options.TimeStepSeconds,
		IssuedAtUnix:     options.IssuedAtUnix,
	}
}

func decryptManyOptions(options *DecryptManyOptions) *DecryptOptions {
	if options == nil {
		return nil
	}

	return &DecryptOptions{
		MaxAgeSeconds:           options.MaxAgeSeconds,
		AllowedClockSkewSeconds: options.AllowedClockSkewSeconds,
		NowUnixSeconds:          options.NowUnixSeconds,
		AllowLegacyPayloads:     options.AllowLegacyPayloads,
	}
}

func resolveBatchSize(value int) int {
	if value <= 0 {
		return defaultBatchSize
	}

	if value > maxParallelBatchSize {
		return maxParallelBatchSize
	}

	return value
}

func reportFileProgress(onProgress func(ProgressInfo), processedBytes int64, totalBytes int64) {
	if onProgress == nil {
		return
	}

	percentage := 100.0
	if totalBytes > 0 {
		percentage = float64(processedBytes) / float64(totalBytes) * 100
	}

	onProgress(ProgressInfo{
		ProcessedBytes: processedBytes,
		TotalBytes:     totalBytes,
		Percentage:     percentage,
	})
}

func reportBatchProgress(onProgress func(BatchProgressInfo), current int, total int) {
	if onProgress == nil || total == 0 {
		return
	}

	onProgress(BatchProgressInfo{
		Current:    current,
		Total:      total,
		Percentage: float64(current) / float64(total) * 100,
	})
}

func optionFileProgress(options *DecryptFileOptions) func(ProgressInfo) {
	if options == nil {
		return nil
	}

	return options.OnProgress
}

func optionEncryptProgress(options *EncryptManyOptions) func(BatchProgressInfo) {
	if options == nil {
		return nil
	}

	return options.OnProgress
}

func optionDecryptProgress(options *DecryptManyOptions) func(BatchProgressInfo) {
	if options == nil {
		return nil
	}

	return options.OnProgress
}
