package encryption

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/K9Crypt/k9crypt-go/src/constants"
)

type Sha512Hasher struct {
	pepper string
	hmacKey string
}

func NewSha512Hasher() *Sha512Hasher {
	return &Sha512Hasher{
		pepper:  constants.Pepper,
		hmacKey: constants.HmacKey,
	}
}

func (s *Sha512Hasher) Hash(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	hasher := sha512.New()
	hasher.Write(data)
	hasher.Write([]byte(s.pepper))

	return hasher.Sum(nil), nil
}

func (s *Sha512Hasher) HashWithSalt(data []byte, salt []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	hasher := sha512.New()
	hasher.Write(salt)
	hasher.Write(data)
	hasher.Write([]byte(s.pepper))

	return hasher.Sum(nil), nil
}

func (s *Sha512Hasher) HmacHash(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	h := hmac.New(sha512.New, []byte(s.hmacKey))
	h.Write(data)
	h.Write([]byte(s.pepper))

	return h.Sum(nil), nil
}

func (s *Sha512Hasher) HmacHashWithSalt(data []byte, salt []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	h := hmac.New(sha512.New, []byte(s.hmacKey))
	h.Write(salt)
	h.Write(data)
	h.Write([]byte(s.pepper))

	return h.Sum(nil), nil
}

func (s *Sha512Hasher) MultiRoundHash(data []byte, rounds int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if rounds <= 0 {
		return nil, fmt.Errorf("rounds must be positive")
	}

	result := data
	for i := 0; i < rounds; i++ {
		hash, err := s.Hash(result)
		if err != nil {
			return nil, fmt.Errorf("failed at round %d: %w", i+1, err)
		}
		result = hash
	}

	return result, nil
}

func (s *Sha512Hasher) MultiRoundHashWithSalt(data []byte, salt []byte, rounds int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	if rounds <= 0 {
		return nil, fmt.Errorf("rounds must be positive")
	}

	result := data
	for i := 0; i < rounds; i++ {
		hash, err := s.HashWithSalt(result, salt)
		if err != nil {
			return nil, fmt.Errorf("failed at round %d: %w", i+1, err)
		}
		result = hash
	}

	return result, nil
}

func (s *Sha512Hasher) Verify(data []byte, hash []byte) bool {
	if len(data) == 0 || len(hash) == 0 {
		return false
	}

	computedHash, err := s.Hash(data)
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

func (s *Sha512Hasher) VerifyWithSalt(data []byte, salt []byte, hash []byte) bool {
	if len(data) == 0 || len(salt) == 0 || len(hash) == 0 {
		return false
	}

	computedHash, err := s.HashWithSalt(data, salt)
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

func (s *Sha512Hasher) HmacVerify(data []byte, hash []byte) bool {
	if len(data) == 0 || len(hash) == 0 {
		return false
	}

	computedHash, err := s.HmacHash(data)
	if err != nil {
		return false
	}

	return hmac.Equal(computedHash, hash)
}

func (s *Sha512Hasher) HmacVerifyWithSalt(data []byte, salt []byte, hash []byte) bool {
	if len(data) == 0 || len(salt) == 0 || len(hash) == 0 {
		return false
	}

	computedHash, err := s.HmacHashWithSalt(data, salt)
	if err != nil {
		return false
	}

	return hmac.Equal(computedHash, hash)
}

func (s *Sha512Hasher) validateInput(data []byte) error {
	if data == nil {
		return fmt.Errorf("input data cannot be nil")
	}

	if len(data) == 0 {
		return fmt.Errorf("input data cannot be empty")
	}

	if len(data) > 1024*1024*10 {
		return fmt.Errorf("input data too large: maximum 10MB allowed")
	}

	return nil
}

func (s *Sha512Hasher) HashWithValidation(data []byte) ([]byte, error) {
	err := s.validateInput(data)
	if err != nil {
		return nil, err
	}

	return s.Hash(data)
}

func (s *Sha512Hasher) HashWithSaltValidation(data []byte, salt []byte) ([]byte, error) {
	err := s.validateInput(data)
	if err != nil {
		return nil, err
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	return s.HashWithSalt(data, salt)
}
