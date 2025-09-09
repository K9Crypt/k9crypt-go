package constants

const (
	SaltSize          = 32
	IvSize            = 16
	KeySize           = 32
	TagSize           = 16
	Pbkdf2Iterations  = 50000
	HashSeed          = 0xcafebabe
	Pepper            = "veryLongAndComplexPepperValue123!@#$%^&*()_+[]{}|;:,.<>?"
	HmacKey           = "veryLongAndComplexHMACKeyValue456!@#$%^&*()_+[]{}|;:,.<>?"
	Argon2SaltSize    = 16
	Argon2HashLength  = 64
	Argon2Time        = 3
	Argon2Memory      = 64 * 1024
	Argon2Threads     = 4
	CompressionLevel  = 6
	BufferSize        = 4096
)

type AesMode string

const (
	AesGcm AesMode = "gcm"
	AesCbc AesMode = "cbc"
	AesCfb AesMode = "cfb"
	AesOfb AesMode = "ofb"
	AesCtr AesMode = "ctr"
)

type CompressionType string

const (
	CompressionZlib CompressionType = "zlib"
	CompressionLzma CompressionType = "lzma"
)