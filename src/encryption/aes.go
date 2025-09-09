package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/K9Crypt/k9crypt-go/src/constants"
)

type AesEncryptor struct {
	modes []constants.AesMode
}

func NewAesEncryptor() *AesEncryptor {
	return &AesEncryptor{
		modes: []constants.AesMode{
			constants.AesGcm,
			constants.AesCbc,
			constants.AesCfb,
			constants.AesOfb,
			constants.AesCtr,
		},
	}
}

func (a *AesEncryptor) GenerateKey() ([]byte, error) {
	key := make([]byte, constants.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

func (a *AesEncryptor) GenerateIv() ([]byte, error) {
	iv := make([]byte, constants.IvSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	return iv, nil
}

func (a *AesEncryptor) MultiLayerEncrypt(data []byte, keys [][]byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if len(keys) != len(a.modes) {
		return nil, fmt.Errorf("number of keys must match number of modes")
	}

	result := data
	for i, mode := range a.modes {
		encrypted, err := a.encryptWithMode(result, keys[i], mode)
		if err != nil {
			return nil, fmt.Errorf("failed at layer %d (%s): %w", i+1, mode, err)
		}
		result = encrypted
	}

	return result, nil
}

func (a *AesEncryptor) MultiLayerDecrypt(data []byte, keys [][]byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if len(keys) != len(a.modes) {
		return nil, fmt.Errorf("number of keys must match number of modes")
	}

	result := data
	for i := len(a.modes) - 1; i >= 0; i-- {
		decrypted, err := a.decryptWithMode(result, keys[i], a.modes[i])
		if err != nil {
			return nil, fmt.Errorf("failed at layer %d (%s): %w", len(a.modes)-i, a.modes[i], err)
		}
		result = decrypted
	}

	return result, nil
}

func (a *AesEncryptor) encryptWithMode(data []byte, key []byte, mode constants.AesMode) ([]byte, error) {
	if len(key) != constants.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", constants.KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if mode == constants.AesGcm {
		return a.encryptGcm(data, block)
	}
	if mode == constants.AesCbc {
		return a.encryptCbc(data, block)
	}
	if mode == constants.AesCfb {
		return a.encryptCfb(data, block)
	}
	if mode == constants.AesOfb {
		return a.encryptOfb(data, block)
	}
	if mode == constants.AesCtr {
		return a.encryptCtr(data, block)
	}

	return nil, fmt.Errorf("unsupported encryption mode: %s", mode)
}

func (a *AesEncryptor) decryptWithMode(data []byte, key []byte, mode constants.AesMode) ([]byte, error) {
	if len(key) != constants.KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", constants.KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if mode == constants.AesGcm {
		return a.decryptGcm(data, block)
	}
	if mode == constants.AesCbc {
		return a.decryptCbc(data, block)
	}
	if mode == constants.AesCfb {
		return a.decryptCfb(data, block)
	}
	if mode == constants.AesOfb {
		return a.decryptOfb(data, block)
	}
	if mode == constants.AesCtr {
		return a.decryptCtr(data, block)
	}

	return nil, fmt.Errorf("unsupported decryption mode: %s", mode)
}

func (a *AesEncryptor) encryptGcm(data []byte, block cipher.Block) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (a *AesEncryptor) decryptGcm(data []byte, block cipher.Block) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func (a *AesEncryptor) encryptCbc(data []byte, block cipher.Block) ([]byte, error) {
	blockSize := block.BlockSize()
	data = a.pkcs7Pad(data, blockSize)

	iv, err := a.GenerateIv()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	mode.CryptBlocks(ciphertext, data)

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

func (a *AesEncryptor) decryptCbc(data []byte, block cipher.Block) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext: not multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return a.pkcs7Unpad(plaintext)
}

func (a *AesEncryptor) encryptCfb(data []byte, block cipher.Block) ([]byte, error) {
	iv, err := a.GenerateIv()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

func (a *AesEncryptor) decryptCfb(data []byte, block cipher.Block) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AesEncryptor) encryptOfb(data []byte, block cipher.Block) ([]byte, error) {
	iv, err := a.GenerateIv()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

func (a *AesEncryptor) decryptOfb(data []byte, block cipher.Block) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	stream := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AesEncryptor) encryptCtr(data []byte, block cipher.Block) ([]byte, error) {
	iv, err := a.GenerateIv()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

func (a *AesEncryptor) decryptCtr(data []byte, block cipher.Block) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data) < blockSize {
		return nil, fmt.Errorf("invalid ciphertext: too short")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AesEncryptor) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func (a *AesEncryptor) pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padding: empty data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

func (a *AesEncryptor) GenerateKeys(count int) ([][]byte, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}

	keys := make([][]byte, count)
	for i := 0; i < count; i++ {
		key, err := a.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key %d: %w", i+1, err)
		}
		keys[i] = key
	}

	return keys, nil
}

func (a *AesEncryptor) validateInput(data []byte) error {
	if data == nil {
		return fmt.Errorf("input data cannot be nil")
	}

	if len(data) == 0 {
		return fmt.Errorf("input data cannot be empty")
	}

	if len(data) > 1024*1024*50 {
		return fmt.Errorf("input data too large: maximum 50MB allowed")
	}

	return nil
}

func (a *AesEncryptor) MultiLayerEncryptWithValidation(data []byte, keys [][]byte) ([]byte, error) {
	err := a.validateInput(data)
	if err != nil {
		return nil, err
	}

	return a.MultiLayerEncrypt(data, keys)
}

func (a *AesEncryptor) MultiLayerDecryptWithValidation(data []byte, keys [][]byte) ([]byte, error) {
	err := a.validateInput(data)
	if err != nil {
		return nil, err
	}

	return a.MultiLayerDecrypt(data, keys)
}

func (a *AesEncryptor) GetModes() []constants.AesMode {
	return a.modes
}

func (a *AesEncryptor) SetModes(modes []constants.AesMode) error {
	if len(modes) == 0 {
		return fmt.Errorf("modes cannot be empty")
	}

	for _, mode := range modes {
		if mode != constants.AesGcm && mode != constants.AesCbc &&
		   mode != constants.AesCfb && mode != constants.AesOfb && mode != constants.AesCtr {
			return fmt.Errorf("unsupported mode: %s", mode)
		}
	}

	a.modes = modes
	return nil
}
