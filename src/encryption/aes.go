package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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
		return nil, errors.New("key generation failed")
	}
	return key, nil
}

func (a *AesEncryptor) GenerateIv() ([]byte, error) {
	iv := make([]byte, constants.IvSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, errors.New("IV generation failed")
	}
	return iv, nil
}

func (a *AesEncryptor) generateIvs(count int) ([][]byte, error) {
	if count <= 0 {
		return nil, errors.New("invalid IV count")
	}

	totalBytes := count * constants.IvSize
	raw := make([]byte, totalBytes)
	_, err := rand.Read(raw)
	if err != nil {
		return nil, errors.New("IV generation failed")
	}

	ivs := make([][]byte, count)
	for i := 0; i < count; i++ {
		ivs[i] = raw[i*constants.IvSize : (i+1)*constants.IvSize]
	}

	return ivs, nil
}

func (a *AesEncryptor) MultiLayerEncrypt(data []byte, keys [][]byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("encryption failed")
	}

	if len(keys) != len(a.modes) {
		return nil, errors.New("encryption failed")
	}

	ivs, err := a.generateIvs(len(a.modes))
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	result := data
	for i, mode := range a.modes {
		encrypted, err := a.encryptWithMode(result, keys[i], mode, ivs[i])
		if err != nil {
			return nil, errors.New("encryption failed")
		}
		result = encrypted
	}

	return result, nil
}

func (a *AesEncryptor) MultiLayerDecrypt(data []byte, keys [][]byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("decryption failed")
	}

	if len(keys) != len(a.modes) {
		return nil, errors.New("decryption failed")
	}

	result := data
	for i := len(a.modes) - 1; i >= 0; i-- {
		decrypted, err := a.decryptWithMode(result, keys[i], a.modes[i])
		if err != nil {
			return nil, errors.New("decryption failed")
		}
		result = decrypted
	}

	return result, nil
}

func (a *AesEncryptor) encryptWithMode(data []byte, key []byte, mode constants.AesMode, iv []byte) ([]byte, error) {
	if len(key) != constants.KeySize {
		return nil, errors.New("encryption failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	if mode == constants.AesGcm {
		return a.encryptGcm(data, block)
	}
	if mode == constants.AesCbc {
		return a.encryptCbc(data, block, iv)
	}
	if mode == constants.AesCfb {
		return a.encryptCfb(data, block, iv)
	}
	if mode == constants.AesOfb {
		return a.encryptOfb(data, block, iv)
	}
	if mode == constants.AesCtr {
		return a.encryptCtr(data, block, iv)
	}

	return nil, errors.New("encryption failed")
}

func (a *AesEncryptor) decryptWithMode(data []byte, key []byte, mode constants.AesMode) ([]byte, error) {
	if len(key) != constants.KeySize {
		return nil, errors.New("decryption failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("decryption failed")
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

	return nil, errors.New("decryption failed")
}

func (a *AesEncryptor) encryptGcm(data []byte, block cipher.Block) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, errors.New("encryption failed")
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (a *AesEncryptor) decryptGcm(data []byte, block cipher.Block) ([]byte, error) {
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("decryption failed")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

func (a *AesEncryptor) encryptCbc(data []byte, block cipher.Block, iv []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	data = a.pkcs7Pad(data, blockSize)

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
		return nil, errors.New("decryption failed")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("decryption failed")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return a.pkcs7Unpad(plaintext)
}

func (a *AesEncryptor) encryptCfb(data []byte, block cipher.Block, iv []byte) ([]byte, error) {
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
		return nil, errors.New("decryption failed")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AesEncryptor) encryptOfb(data []byte, block cipher.Block, iv []byte) ([]byte, error) {
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
		return nil, errors.New("decryption failed")
	}

	iv := data[:blockSize]
	ciphertext := data[blockSize:]

	stream := cipher.NewOFB(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func (a *AesEncryptor) encryptCtr(data []byte, block cipher.Block, iv []byte) ([]byte, error) {
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
		return nil, errors.New("decryption failed")
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
		return nil, errors.New("decryption failed")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("decryption failed")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("decryption failed")
		}
	}

	return data[:len(data)-padding], nil
}

func (a *AesEncryptor) GenerateKeys(count int) ([][]byte, error) {
	if count <= 0 {
		return nil, errors.New("invalid key count")
	}

	keys := make([][]byte, count)
	for i := 0; i < count; i++ {
		key, err := a.GenerateKey()
		if err != nil {
			return nil, errors.New("key generation failed")
		}
		keys[i] = key
	}

	return keys, nil
}

func (a *AesEncryptor) validateInput(data []byte) error {
	if data == nil {
		return errors.New("input data cannot be nil")
	}

	if len(data) == 0 {
		return errors.New("input data cannot be empty")
	}

	if len(data) > 1024*1024*50 {
		return errors.New("input data too large")
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
		return errors.New("modes cannot be empty")
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
