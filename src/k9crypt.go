package k9crypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"github.com/K9Crypt/k9crypt-go/src/compression"
	"github.com/K9Crypt/k9crypt-go/src/constants"
	"github.com/K9Crypt/k9crypt-go/src/encryption"
)

type K9Crypt struct {
	secretKey               []byte
	aesEncryptor            *encryption.AesEncryptor
	sha512Hasher            *encryption.Sha512Hasher
	argon2Hasher            *encryption.Argon2Hasher
	zlibCompressor          *compression.ZlibCompressor
	lzmaCompressor          *compression.LzmaCompressor
	compressionType         constants.CompressionType
	defaultCompressionLevel int
}

type Options struct {
	CompressionLevel int
}

func New(secretKey string) (*K9Crypt, error) {
	var keyBytes []byte

	if secretKey == "" {
		keyBytes = make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, keyBytes)
		if err != nil {
			return nil, errors.New("key generation failed")
		}
	}
	if secretKey != "" {
		keyBytes = []byte(secretKey)
	}

	return &K9Crypt{
		secretKey:               keyBytes,
		aesEncryptor:            encryption.NewAesEncryptor(),
		sha512Hasher:            encryption.NewSha512Hasher(),
		argon2Hasher:            encryption.NewArgon2Hasher(),
		zlibCompressor:          compression.NewZlibCompressor(),
		lzmaCompressor:          compression.NewLzmaCompressor(),
		compressionType:         constants.CompressionZlib,
		defaultCompressionLevel: constants.CompressionLevel,
	}, nil
}

func NewWithKey(secretKey []byte) (*K9Crypt, error) {
	var keyBytes []byte

	if len(secretKey) == 0 {
		keyBytes = make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, keyBytes)
		if err != nil {
			return nil, errors.New("key generation failed")
		}
	}
	if len(secretKey) > 0 {
		keyBytes = make([]byte, len(secretKey))
		copy(keyBytes, secretKey)
	}

	return &K9Crypt{
		secretKey:               keyBytes,
		aesEncryptor:            encryption.NewAesEncryptor(),
		sha512Hasher:            encryption.NewSha512Hasher(),
		argon2Hasher:            encryption.NewArgon2Hasher(),
		zlibCompressor:          compression.NewZlibCompressor(),
		lzmaCompressor:          compression.NewLzmaCompressor(),
		compressionType:         constants.CompressionZlib,
		defaultCompressionLevel: constants.CompressionLevel,
	}, nil
}

func NewWithOptions(secretKey string, compressionLevel int) (*K9Crypt, error) {
	k, err := New(secretKey)
	if err != nil {
		return nil, err
	}
	if compressionLevel < 0 || compressionLevel > 9 {
		return nil, errors.New("compression level must be between 0 and 9")
	}
	k.defaultCompressionLevel = compressionLevel
	k.zlibCompressor.SetLevel(compressionLevel)
	return k, nil
}

func NewWithKeyAndOptions(secretKey []byte, compressionLevel int) (*K9Crypt, error) {
	k, err := NewWithKey(secretKey)
	if err != nil {
		return nil, err
	}
	if compressionLevel < 0 || compressionLevel > 9 {
		return nil, errors.New("compression level must be between 0 and 9")
	}
	k.defaultCompressionLevel = compressionLevel
	k.zlibCompressor.SetLevel(compressionLevel)
	return k, nil
}

func (k *K9Crypt) SetCompressionLevel(level int) error {
	if level < 0 || level > 9 {
		return errors.New("compression level must be between 0 and 9")
	}
	k.defaultCompressionLevel = level
	return k.zlibCompressor.SetLevel(level)
}

func (k *K9Crypt) GetCompressionLevel() int {
	return k.defaultCompressionLevel
}

func (k *K9Crypt) Encrypt(plaintext string) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("encryption failed")
	}

	data := []byte(plaintext)
	if len(data) > constants.MaxPlaintextSize {
		return "", errors.New("encryption failed")
	}

	password := k.secretKey

	compressedData, err := k.compressData(data)
	if err != nil {
		return "", errors.New("encryption failed")
	}

	salt, err := k.argon2Hasher.GenerateSalt()
	if err != nil {
		return "", errors.New("encryption failed")
	}

	keys, err := k.deriveKeys(password, salt)
	if err != nil {
		return "", errors.New("encryption failed")
	}

	encryptedData, err := k.aesEncryptor.MultiLayerEncrypt(compressedData, keys)
	if err != nil {
		return "", errors.New("encryption failed")
	}

	hash, err := k.generateHash(data, salt)
	if err != nil {
		return "", errors.New("encryption failed")
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 131072))
	paddingSizeByte := make([]byte, 1)
	_, err = rand.Read(paddingSizeByte)
	if err != nil {
		return "", errors.New("encryption failed")
	}
	paddingSize := byte(4 + int(paddingSizeByte[0])%13)
	buffer.WriteByte(paddingSize)
	padding := make([]byte, int(paddingSize))
	_, err = rand.Read(padding)
	if err != nil {
		return "", errors.New("encryption failed")
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
		return "", errors.New("decryption failed")
	}

	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	if len(decodedData) > constants.MaxCiphertextSize {
		return "", errors.New("decryption failed")
	}

	if len(decodedData) < constants.MinPayloadSize {
		return "", errors.New("decryption failed")
	}

	reader := bytes.NewReader(decodedData)

	paddingSizeByte := make([]byte, 1)
	_, err = reader.Read(paddingSizeByte)
	if err != nil {
		return "", errors.New("decryption failed")
	}
	paddingSize := int(paddingSizeByte[0])
	padding := make([]byte, paddingSize)
	_, err = reader.Read(padding)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	saltLenBytes := make([]byte, 4)
	_, err = reader.Read(saltLenBytes)
	if err != nil {
		return "", errors.New("decryption failed")
	}
	saltLen := binary.LittleEndian.Uint32(saltLenBytes)

	salt := make([]byte, saltLen)
	_, err = reader.Read(salt)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	hashLenBytes := make([]byte, 4)
	_, err = reader.Read(hashLenBytes)
	if err != nil {
		return "", errors.New("decryption failed")
	}
	hashLen := binary.LittleEndian.Uint32(hashLenBytes)

	hash := make([]byte, hashLen)
	_, err = reader.Read(hash)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	remaining := make([]byte, len(decodedData)-(1+int(paddingSize))-8-int(saltLen)-int(hashLen))
	_, err = reader.Read(remaining)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	keys, err := k.deriveKeys(k.secretKey, salt)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	decryptedData, err := k.aesEncryptor.MultiLayerDecrypt(remaining, keys)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	decompressedData, err := k.decompressData(decryptedData)
	if err != nil {
		return "", errors.New("decryption failed")
	}

	if !k.verifyHash(decompressedData, salt, hash) {
		return "", errors.New("decryption failed")
	}

	return string(decompressedData), nil
}

func (k *K9Crypt) deriveKeys(password []byte, salt []byte) ([][]byte, error) {
	masterKey, err := k.argon2Hasher.Hash(password, salt)
	if err != nil {
		return nil, errors.New("key derivation failed")
	}

	hashedMasterKey, err := k.sha512Hasher.HashWithSalt(masterKey, salt)
	if err != nil {
		return nil, errors.New("key derivation failed")
	}

	keys := make([][]byte, 5)
	keyChan := make(chan struct {
		index int
		key   []byte
		err   error
	}, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			keyMaterial := make([]byte, len(hashedMasterKey)+1)
			copy(keyMaterial, hashedMasterKey)
			keyMaterial[len(hashedMasterKey)] = byte(idx)
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
			return nil, errors.New("key derivation failed")
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
	return nil, errors.New("compression error")
}

func (k *K9Crypt) decompressData(data []byte) ([]byte, error) {
	if k.compressionType == constants.CompressionZlib {
		return k.zlibCompressor.Decompress(data)
	}
	if k.compressionType == constants.CompressionLzma {
		return k.lzmaCompressor.Decompress(data)
	}
	return nil, errors.New("decompression error")
}
