package constants

import (
	"encoding/hex"
)

const (
	SaltSize         = 32
	IvSize           = 16
	KeySize          = 32
	TagSize          = 16
	Pbkdf2Iterations = 600000
	HashSeed         = 0xcafebabe
	Argon2SaltSize   = 16
	Argon2HashLength = 64
	Argon2Time       = 3
	Argon2Memory     = 64 * 1024
	Argon2Threads    = 4
	CompressionLevel = 6
	BufferSize       = 4096

	MaxPlaintextSize  = 1024 * 1024 * 100
	MaxCiphertextSize = 1024 * 1024 * 150
	MinPayloadSize    = 17
	StreamBufferLimit = 1024 * 1024 * 5
)

var (
	Pepper  []byte
	HmacKey []byte
)

func init() {
	var err error

	Pepper, err = hex.DecodeString("766572794c6f6e67416e64436f6d706c657850657070657256616c756531323321402324255e262a28295f2b5b5d7b7d7c3b3a2c2e3c3e3f")
	if err != nil {
		panic(err)
	}

	HmacKey, err = hex.DecodeString("766572794c6f6e67416e64436f6d706c6578484d41434b657956616c756534353621402324255e262a28295f2b5b5d7b7d7c3b3a2c2e3c3e3f")
	if err != nil {
		panic(err)
	}
}

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
