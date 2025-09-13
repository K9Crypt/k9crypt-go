package encryption

import (
	"crypto/rand"
	"fmt"

	"github.com/K9Crypt/k9crypt-go/src/constants"

	"golang.org/x/crypto/argon2"
)

type Argon2Hasher struct {
	time    uint32
	memory  uint32
	threads uint8
	saltLen int
	keyLen  int
}

func NewArgon2Hasher() *Argon2Hasher {
	return &Argon2Hasher{
		time:    1,
		memory:  16 * 1024,
		threads: 1,
		saltLen: constants.Argon2SaltSize,
		keyLen:  constants.Argon2HashLength,
	}
}

func (a *Argon2Hasher) GenerateSalt() ([]byte, error) {
	salt := make([]byte, a.saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func (a *Argon2Hasher) Hash(password []byte, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	hash := argon2.IDKey(password, salt, a.time, a.memory, a.threads, uint32(a.keyLen))
	return hash, nil
}

func (a *Argon2Hasher) HashWithGeneratedSalt(password []byte) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("password cannot be empty")
	}

	salt, err := a.GenerateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hash, err := a.Hash(password, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash password: %w", err)
	}

	return hash, salt, nil
}

func (a *Argon2Hasher) Verify(password []byte, salt []byte, hash []byte) bool {
	if len(password) == 0 || len(salt) == 0 || len(hash) == 0 {
		return false
	}

	computedHash, err := a.Hash(password, salt)
	if err != nil {
		return false
	}

	if len(computedHash) != len(hash) {
		return false
	}

	for i := 0; i < len(computedHash); i++ {
		if computedHash[i] != hash[i] {
			return false
		}
	}

	return true
}

func (a *Argon2Hasher) DeriveKey(password []byte, salt []byte, keyLength uint32) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	if keyLength == 0 {
		return nil, fmt.Errorf("key length must be positive")
	}

	key := argon2.IDKey(password, salt, a.time, a.memory, a.threads, keyLength)
	return key, nil
}

func (a *Argon2Hasher) DeriveKeyWithGeneratedSalt(password []byte, keyLength uint32) ([]byte, []byte, error) {
	if len(password) == 0 {
		return nil, nil, fmt.Errorf("password cannot be empty")
	}

	if keyLength == 0 {
		return nil, nil, fmt.Errorf("key length must be positive")
	}

	salt, err := a.GenerateSalt()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := a.DeriveKey(password, salt, keyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, salt, nil
}

func (a *Argon2Hasher) MultiRoundHash(password []byte, salt []byte, rounds int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	if rounds <= 0 {
		return nil, fmt.Errorf("rounds must be positive")
	}

	result := password
	for i := 0; i < rounds; i++ {
		hash, err := a.Hash(result, salt)
		if err != nil {
			return nil, fmt.Errorf("failed at round %d: %w", i+1, err)
		}
		result = hash
	}

	return result, nil
}

func (a *Argon2Hasher) SetParameters(time uint32, memory uint32, threads uint8) error {
	if time == 0 {
		return fmt.Errorf("time parameter must be positive")
	}

	if memory == 0 {
		return fmt.Errorf("memory parameter must be positive")
	}

	if threads == 0 {
		return fmt.Errorf("threads parameter must be positive")
	}

	a.time = time
	a.memory = memory
	a.threads = threads
	return nil
}

func (a *Argon2Hasher) GetParameters() (uint32, uint32, uint8) {
	return a.time, a.memory, a.threads
}

func (a *Argon2Hasher) SetSaltLength(length int) error {
	if length <= 0 {
		return fmt.Errorf("salt length must be positive")
	}

	if length > 1024 {
		return fmt.Errorf("salt length too large: maximum 1024 bytes allowed")
	}

	a.saltLen = length
	return nil
}

func (a *Argon2Hasher) GetSaltLength() int {
	return a.saltLen
}

func (a *Argon2Hasher) SetKeyLength(length int) error {
	if length <= 0 {
		return fmt.Errorf("key length must be positive")
	}

	if length > 1024 {
		return fmt.Errorf("key length too large: maximum 1024 bytes allowed")
	}

	a.keyLen = length
	return nil
}

func (a *Argon2Hasher) GetKeyLength() int {
	return a.keyLen
}

func (a *Argon2Hasher) validateInput(data []byte) error {
	if data == nil {
		return fmt.Errorf("input data cannot be nil")
	}

	if len(data) == 0 {
		return fmt.Errorf("input data cannot be empty")
	}

	if len(data) > 1024*1024 {
		return fmt.Errorf("input data too large: maximum 1MB allowed")
	}

	return nil
}

func (a *Argon2Hasher) HashWithValidation(password []byte, salt []byte) ([]byte, error) {
	err := a.validateInput(password)
	if err != nil {
		return nil, err
	}

	err = a.validateInput(salt)
	if err != nil {
		return nil, err
	}

	return a.Hash(password, salt)
}
