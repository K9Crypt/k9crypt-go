package k9crypt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/K9Crypt/k9crypt-go/src/constants"
)

const maxSafeInteger = int64(1<<53 - 1)
const maxBase64PayloadLength = ((constants.MaxCiphertextSize + 2) / 3) * 4

type timeMetadata struct {
	version      byte
	flags        byte
	isBinary     bool
	isCompressed bool
	stepSeconds  uint32
	issuedAt     int64
}

type versionedPayload struct {
	version       byte
	header        []byte
	timeMetadata  *timeMetadata
	body          []byte
	salt          []byte
	ivs           [][]byte
	encrypted     []byte
	tag           []byte
	integritySalt []byte
	dataHash      []byte
}

func createTimeHeader(options *EncryptOptions, isBinary bool, isCompressed bool) ([]byte, *timeMetadata, error) {
	issuedAt := time.Now().Unix()
	if options != nil && options.IssuedAtUnix != nil {
		issuedAt = *options.IssuedAtUnix
	}

	if issuedAt < 0 || issuedAt > maxSafeInteger {
		return nil, nil, errors.New("invalid issuedAt")
	}

	stepSeconds := uint32(constants.DefaultTimeStep)
	if options != nil && options.TimeStepSeconds != 0 {
		stepSeconds = options.TimeStepSeconds
	}

	if stepSeconds < 1 || stepSeconds > constants.MaxTimeStep {
		return nil, nil, errors.New("invalid time step")
	}

	flags := byte(constants.PayloadFlagsNone)
	if isBinary {
		flags |= byte(constants.PayloadFlagBinary)
	}
	if !isCompressed {
		flags |= byte(constants.PayloadFlagRaw)
	}

	header := make([]byte, constants.PayloadHeaderSize)
	copy(header, constants.PayloadMagic)
	header[len(constants.PayloadMagic)] = byte(constants.PayloadCurrentVersion)
	header[len(constants.PayloadMagic)+1] = flags
	binary.BigEndian.PutUint32(header[6:10], stepSeconds)
	binary.BigEndian.PutUint64(header[10:18], uint64(issuedAt))

	metadata := &timeMetadata{
		version:      byte(constants.PayloadCurrentVersion),
		flags:        flags,
		isBinary:     isBinary,
		isCompressed: isCompressed,
		stepSeconds:  stepSeconds,
		issuedAt:     issuedAt,
	}

	return header, metadata, nil
}

func decodePayloadString(ciphertext string) ([]byte, error) {
	normalized := strings.TrimSpace(ciphertext)
	if normalized == "" {
		return nil, errors.New("payload is empty")
	}

	if len(normalized) > maxBase64PayloadLength {
		return nil, errors.New("payload too large")
	}

	if len(normalized)%4 != 0 {
		return nil, errors.New("payload must be valid base64")
	}

	data, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, errors.New("payload must be valid base64")
	}

	if len(data) > constants.MaxCiphertextSize {
		return nil, errors.New("payload too large")
	}

	return data, nil
}

func hasVersionedPayload(data []byte) bool {
	if len(data) < len(constants.PayloadMagic) {
		return false
	}

	return bytes.Equal(data[:len(constants.PayloadMagic)], constants.PayloadMagic)
}

func parseVersionedPayload(data []byte) (*versionedPayload, error) {
	if len(data) < constants.MinV2PayloadSize {
		return nil, errors.New("payload too small")
	}

	header := data[:constants.PayloadHeaderSize]
	metadata, err := parsePayloadHeader(header)
	if err != nil {
		return nil, err
	}

	trailerOffset := len(data) - constants.Argon2HashLength - constants.Argon2SaltSize
	tagOffset := trailerOffset - constants.TagSize
	saltOffset := constants.PayloadHeaderSize
	ivOffset := saltOffset + constants.SaltSize
	encryptedOffset := ivOffset + 5*constants.IvSize

	if encryptedOffset >= tagOffset {
		return nil, errors.New("payload too small")
	}

	ivs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		start := ivOffset + i*constants.IvSize
		ivs[i] = data[start : start+constants.IvSize]
	}

	payload := &versionedPayload{
		version:       metadata.version,
		header:        header,
		timeMetadata:  metadata,
		body:          data[:trailerOffset],
		salt:          data[saltOffset:ivOffset],
		ivs:           ivs,
		encrypted:     data[encryptedOffset:tagOffset],
		tag:           data[tagOffset:trailerOffset],
		integritySalt: data[trailerOffset : trailerOffset+constants.Argon2SaltSize],
		dataHash:      data[trailerOffset+constants.Argon2SaltSize:],
	}

	return payload, nil
}

func parseLegacyV1Payload(data []byte) (*versionedPayload, error) {
	if len(data) < constants.MinPayloadSize {
		return nil, errors.New("payload too small")
	}

	trailerOffset := len(data) - constants.Argon2HashLength - constants.Argon2SaltSize
	tagOffset := trailerOffset - constants.TagSize
	saltOffset := 0
	ivOffset := saltOffset + constants.SaltSize
	encryptedOffset := ivOffset + 5*constants.IvSize

	if encryptedOffset >= tagOffset {
		return nil, errors.New("payload too small")
	}

	ivs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		start := ivOffset + i*constants.IvSize
		ivs[i] = data[start : start+constants.IvSize]
	}

	payload := &versionedPayload{
		version:       byte(constants.PayloadVersionV1),
		header:        nil,
		timeMetadata:  nil,
		body:          data[:trailerOffset],
		salt:          data[saltOffset:ivOffset],
		ivs:           ivs,
		encrypted:     data[encryptedOffset:tagOffset],
		tag:           data[tagOffset:trailerOffset],
		integritySalt: data[trailerOffset : trailerOffset+constants.Argon2SaltSize],
		dataHash:      data[trailerOffset+constants.Argon2SaltSize:],
	}

	return payload, nil
}

func parsePayloadHeader(header []byte) (*timeMetadata, error) {
	if len(header) != constants.PayloadHeaderSize {
		return nil, errors.New("invalid payload header")
	}

	if !bytes.Equal(header[:len(constants.PayloadMagic)], constants.PayloadMagic) {
		return nil, errors.New("invalid payload header")
	}

	version := header[len(constants.PayloadMagic)]
	if version != constants.PayloadVersionV2 && version != constants.PayloadVersionV3 && version != constants.PayloadVersionV4 {
		return nil, errors.New("unsupported payload version")
	}

	flags := header[len(constants.PayloadMagic)+1]
	if version == constants.PayloadVersionV2 && flags != byte(constants.PayloadFlagsNone) {
		return nil, errors.New("unsupported payload flags")
	}

	if version >= constants.PayloadVersionV3 && flags&^byte(constants.PayloadSupportedFlags) != 0 {
		return nil, errors.New("unsupported payload flags")
	}

	stepSeconds := binary.BigEndian.Uint32(header[6:10])
	if stepSeconds < 1 || stepSeconds > constants.MaxTimeStep {
		return nil, errors.New("invalid payload time step")
	}

	issuedAt := binary.BigEndian.Uint64(header[10:18])
	if issuedAt > uint64(maxSafeInteger) {
		return nil, errors.New("payload timestamp is too large")
	}

	metadata := &timeMetadata{
		version:      version,
		flags:        flags,
		isBinary:     flags&byte(constants.PayloadFlagBinary) == byte(constants.PayloadFlagBinary),
		isCompressed: flags&byte(constants.PayloadFlagRaw) != byte(constants.PayloadFlagRaw),
		stepSeconds:  stepSeconds,
		issuedAt:     int64(issuedAt),
	}

	return metadata, nil
}

func createPayloadBody(header []byte, salt []byte, ivs [][]byte, encrypted []byte, tag []byte) ([]byte, error) {
	if len(header) != constants.PayloadHeaderSize {
		return nil, errors.New("invalid payload header")
	}

	if len(salt) != constants.SaltSize {
		return nil, errors.New("invalid payload salt")
	}

	if len(ivs) != 5 {
		return nil, errors.New("invalid payload IVs")
	}

	if len(encrypted) == 0 || len(tag) != constants.TagSize {
		return nil, errors.New("invalid encrypted payload")
	}

	body := make([]byte, constants.PayloadHeaderSize+constants.SaltSize+5*constants.IvSize+len(encrypted)+constants.TagSize)
	offset := 0
	copy(body[offset:], header)
	offset += constants.PayloadHeaderSize
	copy(body[offset:], salt)
	offset += constants.SaltSize

	for _, iv := range ivs {
		if len(iv) != constants.IvSize {
			return nil, errors.New("invalid payload IV")
		}
		copy(body[offset:], iv)
		offset += constants.IvSize
	}

	copy(body[offset:], encrypted)
	offset += len(encrypted)
	copy(body[offset:], tag)

	return body, nil
}

func buildPayload(body []byte, integritySalt []byte, dataHash []byte) (string, error) {
	if len(body) < constants.MinV2PayloadSize-constants.Argon2SaltSize-constants.Argon2HashLength {
		return "", errors.New("invalid payload body")
	}

	if len(integritySalt) != constants.Argon2SaltSize {
		return "", errors.New("invalid integrity salt")
	}

	if len(dataHash) != constants.Argon2HashLength {
		return "", errors.New("invalid payload hash")
	}

	result := make([]byte, len(body)+constants.Argon2SaltSize+constants.Argon2HashLength)
	offset := 0
	copy(result[offset:], body)
	offset += len(body)
	copy(result[offset:], integritySalt)
	offset += constants.Argon2SaltSize
	copy(result[offset:], dataHash)

	return base64.StdEncoding.EncodeToString(result), nil
}

func validateFreshness(payload *versionedPayload, options *DecryptOptions) error {
	if payload == nil || payload.timeMetadata == nil {
		return nil
	}

	if options == nil || options.MaxAgeSeconds == nil {
		return nil
	}

	maxAgeSeconds := *options.MaxAgeSeconds
	if maxAgeSeconds < 0 || maxAgeSeconds > maxSafeInteger {
		return errors.New("invalid maxAgeSeconds")
	}

	allowedClockSkewSeconds := options.AllowedClockSkewSeconds
	if allowedClockSkewSeconds < 0 || allowedClockSkewSeconds > maxSafeInteger {
		return errors.New("invalid allowedClockSkewSeconds")
	}

	nowUnixSeconds := time.Now().Unix()
	if options.NowUnixSeconds != nil {
		nowUnixSeconds = *options.NowUnixSeconds
	}

	if nowUnixSeconds < 0 || nowUnixSeconds > maxSafeInteger {
		return errors.New("invalid nowUnixSeconds")
	}

	issuedAt := payload.timeMetadata.issuedAt
	if nowUnixSeconds+allowedClockSkewSeconds < issuedAt {
		return errors.New("payload was issued in the future")
	}

	if nowUnixSeconds > issuedAt+maxAgeSeconds+allowedClockSkewSeconds {
		return errors.New("payload expired")
	}

	return nil
}

func legacyPayloadsAllowed(options *DecryptOptions) bool {
	if options == nil || options.AllowLegacyPayloads == nil {
		return true
	}

	return *options.AllowLegacyPayloads
}
