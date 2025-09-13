package k9crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/K9Crypt/k9crypt-go/src/compression"
	"github.com/K9Crypt/k9crypt-go/src/constants"
	"github.com/K9Crypt/k9crypt-go/src/encryption"
)

type K9Crypt struct {
	secretKey       []byte
	aesEncryptor    *encryption.AesEncryptor
	sha512Hasher    *encryption.Sha512Hasher
	argon2Hasher    *encryption.Argon2Hasher
	zlibCompressor  *compression.ZlibCompressor
	lzmaCompressor  *compression.LzmaCompressor
	compressionType constants.CompressionType
}

func New(secretKey string) *K9Crypt {
	var keyBytes []byte

	if secretKey == "" {
		keyBytes = make([]byte, 32)
		rand.Read(keyBytes)
	}
	if secretKey != "" {
		keyBytes = []byte(secretKey)
	}

	return &K9Crypt{
		secretKey:       keyBytes,
		aesEncryptor:    encryption.NewAesEncryptor(),
		sha512Hasher:    encryption.NewSha512Hasher(),
		argon2Hasher:    encryption.NewArgon2Hasher(),
		zlibCompressor:  compression.NewZlibCompressor(),
		lzmaCompressor:  compression.NewLzmaCompressor(),
		compressionType: constants.CompressionZlib,
	}
}

func (k *K9Crypt) Encrypt(plaintext string) (string, error) {
	if len(plaintext) == 0 {
		return "", fmt.Errorf("input data cannot be empty")
	}

	data := []byte(plaintext)
	password := k.secretKey

	compressedData, err := k.compressData(data)
	if err != nil {
		return "", fmt.Errorf("compression failed: %w", err)
	}

	salt, err := k.argon2Hasher.GenerateSalt()
	if err != nil {
		return "", fmt.Errorf("salt generation failed: %w", err)
	}

	keys, err := k.deriveKeys(password, salt)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	encryptedData, err := k.aesEncryptor.MultiLayerEncrypt(compressedData, keys)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	hash, err := k.generateHash(data, salt)
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

	buffer.Write(encryptedData)

	return base64.StdEncoding.EncodeToString(buffer.Bytes()), nil
}

func (k *K9Crypt) Decrypt(encryptedData string) (string, error) {
	if len(encryptedData) == 0 {
		return "", fmt.Errorf("encrypted data cannot be empty")
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("invalid base64 data: %w", err)
	}

	if len(decodedData) < 13 { // minimum 1 + 4 + 8
		return "", fmt.Errorf("invalid encrypted data format")
	}

	reader := bytes.NewReader(decodedData)

	paddingSizeByte := make([]byte, 1)
	_, err = reader.Read(paddingSizeByte)
	if err != nil {
		return "", fmt.Errorf("failed to read padding size: %w", err)
	}
	paddingSize := int(paddingSizeByte[0])
	padding := make([]byte, paddingSize)
	_, err = reader.Read(padding)
	if err != nil {
		return "", fmt.Errorf("failed to read padding: %w", err)
	}

	saltLenBytes := make([]byte, 4)
	_, err = reader.Read(saltLenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read salt length: %w", err)
	}
	saltLen := binary.LittleEndian.Uint32(saltLenBytes)

	salt := make([]byte, saltLen)
	_, err = reader.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to read salt: %w", err)
	}

	hashLenBytes := make([]byte, 4)
	_, err = reader.Read(hashLenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read hash length: %w", err)
	}
	hashLen := binary.LittleEndian.Uint32(hashLenBytes)

	hash := make([]byte, hashLen)
	_, err = reader.Read(hash)
	if err != nil {
		return "", fmt.Errorf("failed to read hash: %w", err)
	}

	remaining := make([]byte, len(decodedData)-(1+int(paddingSize))-8-int(saltLen)-int(hashLen))
	_, err = reader.Read(remaining)
	if err != nil {
		return "", fmt.Errorf("failed to read encrypted data: %w", err)
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	decryptedData, err := k.aesEncryptor.MultiLayerDecrypt(remaining, keys)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	decompressedData, err := k.decompressData(decryptedData)
	if err != nil {
		return "", fmt.Errorf("decompression failed: %w", err)
	}

	if !k.verifyHash(decompressedData, salt, hash) {
		return "", fmt.Errorf("hash verification failed: data integrity compromised")
	}

	return string(decompressedData), nil
}

func (k *K9Crypt) deriveKeys(password []byte, salt []byte) ([][]byte, error) {
	masterKey, err := k.argon2Hasher.Hash(password, salt)
	if err != nil {
		return nil, fmt.Errorf("master key derivation failed: %w", err)
	}

	hashedMasterKey, err := k.sha512Hasher.HashWithSalt(masterKey, salt)
	if err != nil {
		return nil, fmt.Errorf("master key hashing failed: %w", err)
	}

	keys := make([][]byte, 5)
	keyChan := make(chan struct {
		index int
		key   []byte
		err   error
	}, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			keyMaterial := append(hashedMasterKey, byte(idx))
			keyHash, err := k.sha512Hasher.Hash(keyMaterial)
			if err != nil {
				keyChan <- struct {
					index int
					key   []byte
					err   error
				}{idx, nil, err}
				return
			}
			keyChan <- struct {
				index int
				key   []byte
				err   error
			}{idx, keyHash[:constants.KeySize], nil}
		}(i)
	}

	for i := 0; i < 5; i++ {
		result := <-keyChan
		if result.err != nil {
			return nil, fmt.Errorf("key %d derivation failed: %w", result.index+1, result.err)
		}
		keys[result.index] = result.key
	}

	return keys, nil
}

func (k *K9Crypt) generateHash(data []byte, salt []byte) ([]byte, error) {
	return k.sha512Hasher.HmacHashWithSalt(data, salt)
}

func (k *K9Crypt) verifyHash(data []byte, salt []byte, expectedHash []byte) bool {
	return k.sha512Hasher.HmacVerifyWithSalt(data, salt, expectedHash)
}

func (k *K9Crypt) compressData(data []byte) ([]byte, error) {
	if k.compressionType == constants.CompressionZlib {
		return k.zlibCompressor.Compress(data)
	}
	if k.compressionType == constants.CompressionLzma {
		return k.lzmaCompressor.Compress(data)
	}
	return nil, fmt.Errorf("unsupported compression type: %s", k.compressionType)
}

func (k *K9Crypt) decompressData(data []byte) ([]byte, error) {
	if k.compressionType == constants.CompressionZlib {
		return k.zlibCompressor.Decompress(data)
	}
	if k.compressionType == constants.CompressionLzma {
		return k.lzmaCompressor.Decompress(data)
	}
	return nil, fmt.Errorf("unsupported compression type: %s", k.compressionType)
}
