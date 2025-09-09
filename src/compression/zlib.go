package compression

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"io"
	"github.com/K9Crypt/k9crypt-go/src/constants"
)

type ZlibCompressor struct {
	level int
}

func NewZlibCompressor() *ZlibCompressor {
	return &ZlibCompressor{
		level: constants.CompressionLevel,
	}
}

func (z *ZlibCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	var compressed bytes.Buffer

	zlibHeader := []byte{0x78, 0x9c}
	compressed.Write(zlibHeader)

	deflateWriter, err := flate.NewWriter(&compressed, z.level)
	if err != nil {
		return nil, fmt.Errorf("failed to create deflate writer: %w", err)
	}

	_, err = deflateWriter.Write(data)
	if err != nil {
		deflateWriter.Close()
		return nil, fmt.Errorf("failed to write compressed data: %w", err)
	}

	err = deflateWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close deflate writer: %w", err)
	}

	checksum := adler32.Checksum(data)
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, checksum)
	compressed.Write(checksumBytes)

	return compressed.Bytes(), nil
}

func (z *ZlibCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("invalid zlib data: too short")
	}

	if data[0] != 0x78 {
		return nil, fmt.Errorf("invalid zlib header")
	}

	reader := bytes.NewReader(data[2 : len(data)-4])
	deflateReader := flate.NewReader(reader)

	var decompressed bytes.Buffer
	_, err := io.Copy(&decompressed, deflateReader)
	if err != nil {
		deflateReader.Close()
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	err = deflateReader.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close deflate reader: %w", err)
	}

	expectedChecksum := binary.BigEndian.Uint32(data[len(data)-4:])
	actualChecksum := adler32.Checksum(decompressed.Bytes())

	if expectedChecksum != actualChecksum {
		return nil, fmt.Errorf("checksum verification failed")
	}

	return decompressed.Bytes(), nil
}

func (z *ZlibCompressor) validateInput(data []byte) error {
	if data == nil {
		return fmt.Errorf("input data cannot be nil")
	}

	if len(data) == 0 {
		return fmt.Errorf("input data cannot be empty")
	}

	if len(data) > 1024*1024*100 {
		return fmt.Errorf("input data too large: maximum 100MB allowed")
	}

	return nil
}

func (z *ZlibCompressor) CompressWithValidation(data []byte) ([]byte, error) {
	err := z.validateInput(data)
	if err != nil {
		return nil, err
	}

	return z.Compress(data)
}

func (z *ZlibCompressor) DecompressWithValidation(data []byte) ([]byte, error) {
	err := z.validateInput(data)
	if err != nil {
		return nil, err
	}

	return z.Decompress(data)
}

func (z *ZlibCompressor) GetCompressionRatio(original, compressed []byte) float64 {
	if len(original) == 0 {
		return 0.0
	}
	return float64(len(compressed)) / float64(len(original))
}

func (z *ZlibCompressor) CalculateCrc32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func (z *ZlibCompressor) SetLevel(level int) error {
	if level < flate.NoCompression || level > flate.BestCompression {
		return fmt.Errorf("invalid compression level: must be between %d and %d",
			flate.NoCompression, flate.BestCompression)
	}
	z.level = level
	return nil
}

func (z *ZlibCompressor) GetLevel() int {
	return z.level
}
