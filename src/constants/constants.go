package constants

import (
	"encoding/hex"
)

const (
	PayloadCurrentVersion = 4
	PayloadVersionV1      = 1
	PayloadVersionV2      = 2
	PayloadVersionV3      = 3
	PayloadVersionV4      = 4
	PayloadFlagsNone      = 0
	PayloadFlagBinary     = 1
	PayloadFlagRaw        = 2
	PayloadSupportedFlags = PayloadFlagBinary | PayloadFlagRaw
	PayloadHeaderSize     = 18
	DefaultTimeStep       = 300
	MaxTimeStep           = 86400
	GeneratedKeySize      = 50
	SaltSize              = 32
	IvSize                = 16
	KeySize               = 32
	TagSize               = 16
	Pbkdf2Iterations      = 600000
	HashSeed              = 0xcafebabe
	Argon2SaltSize        = 16
	Argon2HashLength      = 64
	Argon2Time            = 3
	Argon2Memory          = 64 * 1024
	Argon2Threads         = 4
	CompressionLevel      = 0
	BufferSize            = 4096

	MaxPlaintextSize     = 1024 * 1024 * 100
	MaxBufferedFileSize  = 1024 * 1024 * 16
	MaxCiphertextSize    = 1024 * 1024 * 200
	MinPayloadSize       = SaltSize + 5*IvSize + 1 + TagSize + Argon2SaltSize + Argon2HashLength
	MinV2PayloadSize     = PayloadHeaderSize + MinPayloadSize
	LegacyMinPayloadSize = 1 + 4 + Argon2SaltSize + 4 + Argon2HashLength + 1
	StreamBufferLimit    = 1024 * 1024 * 5
)

var (
	PayloadMagic   = []byte{0x4b, 0x39, 0x43, 0x32}
	TimeKeyContext = []byte("k9crypt:time-key:v1")
	Pepper         []byte
	HmacKey        []byte
	PayloadPepper  []byte
	PayloadHmacKey []byte
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

	PayloadPepper, err = hex.DecodeString("6b39637279707470657070657276616c7565313233214023242526272829")
	if err != nil {
		panic(err)
	}

	PayloadHmacKey, err = hex.DecodeString("6b396372797074686d61636b657976616c7565343536214023242526272829")
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
