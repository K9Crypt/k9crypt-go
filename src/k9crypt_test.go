package k9crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/K9Crypt/k9crypt-go/src/constants"
	"golang.org/x/crypto/argon2"
)

func TestVersionedStringRoundTripAndHeader(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := int64(1700000000)
	encrypted, err := encryptor.EncryptWithOptions("time scoped payload", &EncryptOptions{
		IssuedAtUnix:    &issuedAt,
		TimeStepSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decoded[:len(constants.PayloadMagic)], constants.PayloadMagic) {
		t.Fatal("payload magic mismatch")
	}

	if decoded[len(constants.PayloadMagic)] != byte(constants.PayloadCurrentVersion) {
		t.Fatalf("expected version %d", constants.PayloadCurrentVersion)
	}

	if decoded[len(constants.PayloadMagic)+1]&byte(constants.PayloadFlagRaw) == 0 {
		t.Fatal("raw flag must be set by default")
	}

	if binary.BigEndian.Uint32(decoded[6:10]) != 300 {
		t.Fatal("time step mismatch")
	}

	if int64(binary.BigEndian.Uint64(decoded[10:18])) != issuedAt {
		t.Fatal("issuedAt mismatch")
	}

	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != "time scoped payload" {
		t.Fatalf("unexpected plaintext: %q", decrypted)
	}
}

func TestVersionedPayloadRejectsHeaderTampering(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.Encrypt("authenticated metadata")
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	decoded[17] ^= 1
	tampered := base64.StdEncoding.EncodeToString(decoded)
	_, err = encryptor.Decrypt(tampered)
	if err == nil {
		t.Fatal("tampered header decrypted successfully")
	}
}

func TestVersionedPayloadRejectsMalformedVersionWithoutLegacyFallback(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.Encrypt("no downgrade")
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	decoded[len(constants.PayloadMagic)] = 99
	malformed := base64.StdEncoding.EncodeToString(decoded)
	_, err = encryptor.Decrypt(malformed)
	if err == nil {
		t.Fatal("malformed versioned payload fell back to legacy")
	}
}

func TestFreshnessPolicyRejectsExpiredPayload(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := int64(1000)
	encrypted, err := encryptor.EncryptWithOptions("expires", &EncryptOptions{IssuedAtUnix: &issuedAt})
	if err != nil {
		t.Fatal(err)
	}

	maxAge := int64(10)
	now := int64(2000)
	_, err = encryptor.DecryptWithOptions(encrypted, &DecryptOptions{
		MaxAgeSeconds:  &maxAge,
		NowUnixSeconds: &now,
	})
	if err == nil {
		t.Fatal("expired payload decrypted successfully")
	}
}

func TestBinaryRoundTrip(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	emptyEncrypted, err := encryptor.EncryptBytes(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	emptyDecrypted, err := encryptor.DecryptBytes(emptyEncrypted, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(emptyDecrypted) != 0 {
		t.Fatal("nil binary plaintext should round trip as empty")
	}

	plaintext := []byte{0x00, 0xff, 0x10, 0x80, 0x7f}
	encrypted, err := encryptor.EncryptBytes(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decoded[len(constants.PayloadMagic)+1]&byte(constants.PayloadFlagBinary) == 0 {
		t.Fatal("binary flag was not set")
	}

	decrypted, err := encryptor.DecryptBytes(encrypted, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("binary plaintext mismatch")
	}
}

func TestCompressedVersionedPayloadRoundTrip(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	level := 6
	encrypted, err := encryptor.EncryptWithOptions("compress me compress me compress me", &EncryptOptions{CompressionLevel: &level})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decoded[len(constants.PayloadMagic)+1]&byte(constants.PayloadFlagRaw) != 0 {
		t.Fatal("raw flag must not be set for compressed payloads")
	}

	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != "compress me compress me compress me" {
		t.Fatal("compressed round trip mismatch")
	}
}

func TestGeneratedKeyAndSecretClone(t *testing.T) {
	generated, err := NewGenerated()
	if err != nil {
		t.Fatal(err)
	}

	keyCopy := generated.GetGenerated()
	if len(keyCopy) != constants.GeneratedKeySize {
		t.Fatal("generated key size mismatch")
	}

	keyCopy[0] ^= 1
	if bytes.Equal(keyCopy, generated.GetGenerated()) {
		t.Fatal("generated key copy mutated internal key")
	}

	secret := []byte("VeryLongSecretKey!@#1234567890")
	encryptor, err := NewWithKey(secret)
	if err != nil {
		t.Fatal(err)
	}

	secret[0] ^= 1
	encrypted, err := encryptor.Encrypt("clone check")
	if err != nil {
		t.Fatal(err)
	}

	mutatedEncryptor, err := NewWithKey(secret)
	if err != nil {
		t.Fatal(err)
	}

	_, err = mutatedEncryptor.Decrypt(encrypted)
	if err == nil {
		t.Fatal("mutated caller key decrypted payload")
	}
}

func TestBatchEmptyInputReturnsEmptySlices(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.EncryptMany([]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted) != 0 {
		t.Fatal("expected empty encrypted batch")
	}

	decrypted, err := encryptor.DecryptMany([]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != 0 {
		t.Fatal("expected empty decrypted batch")
	}
}

func TestConstructorsAndCompressionValidation(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatal("empty string secret was accepted")
	}

	_, err = NewWithKey([]byte{})
	if err == nil {
		t.Fatal("empty byte secret was accepted")
	}

	encryptor, err := NewWithOptions("VeryLongSecretKey!@#1234567890", 3)
	if err != nil {
		t.Fatal(err)
	}

	if encryptor.GetCompressionLevel() != 3 {
		t.Fatal("compression level mismatch")
	}

	err = encryptor.SetCompressionLevel(10)
	if err == nil {
		t.Fatal("invalid compression level was accepted")
	}

	if encryptor.GetGenerated() != nil {
		t.Fatal("caller-provided secret reported generated key")
	}

	nilKeyEncryptor, err := NewWithKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(nilKeyEncryptor.GetGenerated()) != constants.GeneratedKeySize {
		t.Fatal("nil byte secret did not generate a key")
	}

	_, err = NewWithKeyAndOptions([]byte("VeryLongSecretKey!@#1234567890"), 1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewGeneratedWithOptions(2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewWithOptions("VeryLongSecretKey!@#1234567890", 10)
	if err == nil {
		t.Fatal("invalid NewWithOptions compression level was accepted")
	}

	_, err = NewWithKeyAndOptions([]byte("VeryLongSecretKey!@#1234567890"), 10)
	if err == nil {
		t.Fatal("invalid NewWithKeyAndOptions compression level was accepted")
	}

	_, err = NewGeneratedWithOptions(10)
	if err == nil {
		t.Fatal("invalid NewGeneratedWithOptions compression level was accepted")
	}
}

func TestFileRoundTripProgressAndLimit(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	progressCalls := 0
	plaintext := []byte("buffered file payload")
	encrypted, err := encryptor.EncryptFile(plaintext, &EncryptFileOptions{
		CompressionLevel: 6,
		OnProgress: func(info ProgressInfo) {
			progressCalls++
			if info.Percentage != 100 {
				t.Fatalf("unexpected encrypt progress: %f", info.Percentage)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := encryptor.DecryptFile(encrypted, &DecryptFileOptions{
		OnProgress: func(info ProgressInfo) {
			progressCalls++
			if info.Percentage != 100 {
				t.Fatalf("unexpected decrypt progress: %f", info.Percentage)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("file round trip mismatch")
	}

	if progressCalls != 2 {
		t.Fatal("progress callbacks were not called")
	}

	_, err = encryptor.EncryptFile(make([]byte, constants.MaxBufferedFileSize+1), nil)
	if err == nil {
		t.Fatal("oversized file payload was accepted")
	}
}

func TestBatchSequentialParallelAndSkipInvalid(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	items := []string{"alpha", "", "gamma"}
	progressCalls := 0
	encrypted, err := encryptor.EncryptMany(items, &EncryptManyOptions{
		OnProgress: func(info BatchProgressInfo) {
			progressCalls++
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if progressCalls != len(items) {
		t.Fatal("sequential batch progress mismatch")
	}

	decrypted, err := encryptor.DecryptMany(encrypted, &DecryptManyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !stringSlicesEqual(decrypted, items) {
		t.Fatal("sequential batch round trip mismatch")
	}

	parallelEncrypted, err := encryptor.EncryptMany(items, &EncryptManyOptions{Parallel: true, BatchSize: 50})
	if err != nil {
		t.Fatal(err)
	}

	parallelDecrypted, err := encryptor.DecryptMany(parallelEncrypted, &DecryptManyOptions{Parallel: true, BatchSize: 50})
	if err != nil {
		t.Fatal(err)
	}

	if !stringSlicesEqual(parallelDecrypted, items) {
		t.Fatal("parallel batch round trip mismatch")
	}

	mixed := []string{parallelEncrypted[0], "invalid", parallelEncrypted[2]}
	skipped, err := encryptor.DecryptMany(mixed, &DecryptManyOptions{SkipInvalid: true})
	if err != nil {
		t.Fatal(err)
	}

	if skipped[0] != items[0] || skipped[1] != "" || skipped[2] != items[2] {
		t.Fatal("skip invalid result mismatch")
	}
}

func TestLegacyV1PayloadCompatibility(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	legacy := buildLegacyV1Payload(t, encryptor, []byte("legacy v1 string"))
	decrypted, err := encryptor.Decrypt(legacy)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != "legacy v1 string" {
		t.Fatal("legacy v1 string mismatch")
	}

	allowLegacy := false
	_, err = encryptor.DecryptWithOptions(legacy, &DecryptOptions{AllowLegacyPayloads: &allowLegacy})
	if err == nil {
		t.Fatal("strict legacy policy accepted legacy v1 payload")
	}
}

func TestLegacyPayloadCompatibility(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	legacy := buildLegacyPayload(t, encryptor, []byte("legacy string"))
	decrypted, err := encryptor.Decrypt(legacy)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != "legacy string" {
		t.Fatal("legacy string mismatch")
	}

	allowLegacy := false
	_, err = encryptor.DecryptWithOptions(legacy, &DecryptOptions{AllowLegacyPayloads: &allowLegacy})
	if err == nil {
		t.Fatal("strict legacy policy accepted legacy payload")
	}
}

func TestLegacyFilePayloadCompatibility(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	legacy := buildLegacyFilePayload(t, encryptor, []byte("legacy file"))
	decrypted, err := encryptor.DecryptFile(legacy, nil)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != "legacy file" {
		t.Fatal("legacy file mismatch")
	}
}

func TestLegacyHashHelpersAndCompressionBranches(t *testing.T) {
	encryptor, err := New("VeryLongSecretKey!@#1234567890")
	if err != nil {
		t.Fatal(err)
	}

	salt := bytes.Repeat([]byte{7}, constants.Argon2SaltSize)
	body := []byte("versioned legacy body")
	digest := computeVersionedHmac(body, nil)
	expected := argon2.IDKey(digest, salt, constants.Argon2Time, constants.Argon2Memory, constants.Argon2Threads, constants.Argon2HashLength)
	zeroBytes(digest)

	if !verifyVersionedHash(body, expected, salt, nil) {
		t.Fatal("legacy v2 hash verification failed")
	}

	authKey := []byte("VeryLongSecretKey!@#1234567890")
	authDigest := computeVersionedHmac(body, authKey)
	authExpected := argon2.IDKey(authDigest, salt, constants.Argon2Time, constants.Argon2Memory, constants.Argon2Threads, constants.Argon2HashLength)
	zeroBytes(authDigest)

	if !verifyVersionedHash(body, authExpected, salt, authKey) {
		t.Fatal("legacy v3 hash verification failed")
	}

	if encryptor.resolveHashAuthKey(&versionedPayload{version: constants.PayloadVersionV3}) == nil {
		t.Fatal("v3 auth key was not resolved")
	}

	if encryptor.resolveHashAuthKey(&versionedPayload{version: constants.PayloadVersionV2}) != nil {
		t.Fatal("v2 auth key should be nil")
	}

	encryptor.compressionType = constants.CompressionLzma
	compressed, err := encryptor.compressData([]byte("aaaaabaaaaabaaaaab"))
	if err != nil {
		t.Fatal(err)
	}

	decompressed, err := encryptor.decompressData(compressed)
	if err != nil {
		t.Fatal(err)
	}

	if string(decompressed) != "aaaaabaaaaabaaaaab" {
		t.Fatal("lzma branch round trip mismatch")
	}

	encryptor.compressionType = constants.CompressionType("invalid")
	_, err = encryptor.compressData([]byte("x"))
	if err == nil {
		t.Fatal("invalid compression type was accepted")
	}

	_, err = encryptor.decompressData([]byte("x"))
	if err == nil {
		t.Fatal("invalid decompression type was accepted")
	}
}

func buildLegacyV1Payload(t *testing.T, encryptor *K9Crypt, plaintext []byte) string {
	t.Helper()

	compressed, err := encryptor.compressData(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	salt, err := secureRandomBytes(constants.SaltSize)
	if err != nil {
		t.Fatal(err)
	}

	key, err := encryptor.derivePayloadKey(salt, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)

	encrypted, err := encryptor.aesEncryptor.EncryptVersioned(compressed, key, nil)
	if err != nil {
		t.Fatal(err)
	}

	body, err := createLegacyV1Body(salt, encrypted.Ivs, encrypted.Encrypted, encrypted.Tag)
	if err != nil {
		t.Fatal(err)
	}

	integritySalt, err := secureRandomBytes(constants.Argon2SaltSize)
	if err != nil {
		t.Fatal(err)
	}

	digest := computeVersionedHmac(body, nil)
	hash := argon2.IDKey(digest, integritySalt, constants.Argon2Time, constants.Argon2Memory, constants.Argon2Threads, constants.Argon2HashLength)
	zeroBytes(digest)

	result := make([]byte, 0, len(body)+len(integritySalt)+len(hash))
	result = append(result, body...)
	result = append(result, integritySalt...)
	result = append(result, hash...)
	return base64.StdEncoding.EncodeToString(result)
}

func createLegacyV1Body(salt []byte, ivs [][]byte, encrypted []byte, tag []byte) ([]byte, error) {
	if len(salt) != constants.SaltSize || len(ivs) != 5 || len(encrypted) == 0 || len(tag) != constants.TagSize {
		return nil, errors.New("invalid legacy v1 payload")
	}

	body := make([]byte, constants.SaltSize+5*constants.IvSize+len(encrypted)+constants.TagSize)
	offset := 0
	copy(body[offset:], salt)
	offset += constants.SaltSize

	for _, iv := range ivs {
		if len(iv) != constants.IvSize {
			return nil, errors.New("invalid legacy v1 iv")
		}
		copy(body[offset:], iv)
		offset += constants.IvSize
	}

	copy(body[offset:], encrypted)
	offset += len(encrypted)
	copy(body[offset:], tag)
	return body, nil
}

func buildLegacyPayload(t *testing.T, encryptor *K9Crypt, plaintext []byte) string {
	t.Helper()

	compressed, err := encryptor.compressData(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	salt, err := encryptor.argon2Hasher.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := encryptor.deriveKeys(encryptor.secretKey, salt)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.aesEncryptor.MultiLayerEncrypt(compressed, keys)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := encryptor.generateHash(plaintext, salt)
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(nil)
	buffer.WriteByte(4)
	buffer.Write([]byte{1, 2, 3, 4})
	writeLittleBytes(buffer, salt)
	writeLittleBytes(buffer, hash)
	buffer.Write(encrypted)

	return base64.StdEncoding.EncodeToString(buffer.Bytes())
}

func buildLegacyFilePayload(t *testing.T, encryptor *K9Crypt, plaintext []byte) string {
	t.Helper()

	salt, err := encryptor.argon2Hasher.GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := encryptor.deriveKeys(encryptor.secretKey, salt)
	if err != nil {
		t.Fatal(err)
	}

	compressed, err := encryptor.compressData(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := encryptor.aesEncryptor.MultiLayerEncrypt(compressed, keys)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := encryptor.generateHash(plaintext, salt)
	if err != nil {
		t.Fatal(err)
	}

	buffer := bytes.NewBuffer(nil)
	buffer.WriteByte(4)
	buffer.Write([]byte{1, 2, 3, 4})
	writeLittleBytes(buffer, salt)
	writeLittleBytes(buffer, hash)
	chunkCount := make([]byte, 4)
	binary.LittleEndian.PutUint32(chunkCount, 1)
	buffer.Write(chunkCount)
	writeLittleBytes(buffer, encrypted)

	return base64.StdEncoding.EncodeToString(buffer.Bytes())
}

func writeLittleBytes(buffer *bytes.Buffer, data []byte) {
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(data)))
	buffer.Write(length)
	buffer.Write(data)
}

func stringSlicesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
