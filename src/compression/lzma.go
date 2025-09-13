package compression

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type LzmaCompressor struct {
	dictionary []byte
	windowSize int
	hashTable  map[uint32][]int
}

func NewLzmaCompressor() *LzmaCompressor {
	return &LzmaCompressor{
		dictionary: make([]byte, 1<<17),
		windowSize: 1 << 17,
		hashTable:  make(map[uint32][]int),
	}
}

func (lzma *LzmaCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}

	result := bytes.NewBuffer(make([]byte, 0, 131072))

	err := lzma.writeHeader(result, len(data))
	if err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	compressed, err := lzma.simpleCompress(data)
	if err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	result.Write(compressed)
	return result.Bytes(), nil
}

func (lzma *LzmaCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("invalid LZMA data: too short")
	}

	reader := bytes.NewReader(data)

	originalSize, err := lzma.readHeader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	remaining := make([]byte, len(data)-13)
	_, err = reader.Read(remaining)
	if err != nil {
		return nil, fmt.Errorf("failed to read compressed data: %w", err)
	}

	decompressed, err := lzma.simpleDecompress(remaining, originalSize)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	return decompressed, nil
}

func (lzma *LzmaCompressor) writeHeader(writer io.Writer, originalSize int) error {
	properties := byte(0x5d)
	_, err := writer.Write([]byte{properties})
	if err != nil {
		return err
	}

	dictSize := uint32(lzma.windowSize)
	dictSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(dictSizeBytes, dictSize)
	_, err = writer.Write(dictSizeBytes)
	if err != nil {
		return err
	}

	uncompressedSizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(uncompressedSizeBytes, uint64(originalSize))
	_, err = writer.Write(uncompressedSizeBytes)
	if err != nil {
		return err
	}

	return nil
}

func (lzma *LzmaCompressor) readHeader(reader io.Reader) (int, error) {
	propertiesByte := make([]byte, 1)
	_, err := reader.Read(propertiesByte)
	if err != nil {
		return 0, err
	}

	dictSizeBytes := make([]byte, 4)
	_, err = reader.Read(dictSizeBytes)
	if err != nil {
		return 0, err
	}

	uncompressedSizeBytes := make([]byte, 8)
	_, err = reader.Read(uncompressedSizeBytes)
	if err != nil {
		return 0, err
	}

	originalSize := int(binary.LittleEndian.Uint64(uncompressedSizeBytes))
	return originalSize, nil
}

func (lzma *LzmaCompressor) simpleCompress(data []byte) ([]byte, error) {
	result := bytes.NewBuffer(make([]byte, 0, 65536))

	lzma.buildHashTable(data)

	pos := 0
	for pos < len(data) {
		match := lzma.findLongestMatch(data, pos)

		if match.length >= 3 && match.distance > 0 {
			lzma.encodeMatch(result, match.length, match.distance)
			pos += match.length
		}
		if match.length < 3 || match.distance == 0 {
			lzma.encodeLiteral(result, data[pos])
			pos++
		}
	}

	return result.Bytes(), nil
}

func (lzma *LzmaCompressor) simpleDecompress(data []byte, originalSize int) ([]byte, error) {
	result := bytes.NewBuffer(make([]byte, 0, 131072))
	reader := bytes.NewReader(data)

	for result.Len() < originalSize {
		controlByte, err := reader.ReadByte()
		if err != nil {
			break
		}

		if controlByte&0x80 == 0 {
			result.WriteByte(controlByte)
		}
		if controlByte&0x80 != 0 {
			lengthByte, err := reader.ReadByte()
			if err != nil {
				break
			}

			distanceBytes := make([]byte, 2)
			_, err = reader.Read(distanceBytes)
			if err != nil {
				break
			}

			length := int(lengthByte) + 3
			distance := int(binary.LittleEndian.Uint16(distanceBytes))

			if distance > result.Len() {
				break
			}

			for i := 0; i < length && result.Len() < originalSize; i++ {
				resultBytes := result.Bytes()
				pos := len(resultBytes) - distance
				if pos >= 0 && pos < len(resultBytes) {
					result.WriteByte(resultBytes[pos])
				}
			}
		}
	}

	resultBytes := result.Bytes()
	if len(resultBytes) < originalSize {
		return resultBytes, nil
	}
	return resultBytes[:originalSize], nil
}

type Match struct {
	length   int
	distance int
}

func (lzma *LzmaCompressor) findLongestMatch(data []byte, pos int) Match {
	if pos >= len(data)-3 {
		return Match{length: 0, distance: 0}
	}

	hash := lzma.computeHash(data, pos)
	candidates, exists := lzma.hashTable[hash]
	if !exists {
		return Match{length: 0, distance: 0}
	}

	bestLength := 0
	bestDistance := 0
	maxDistance := 131072

	if pos < maxDistance {
		maxDistance = pos
	}

	for _, candidate := range candidates {
		distance := pos - candidate
		if distance > maxDistance || distance <= 0 {
			continue
		}

		length := 0
		maxLength := len(data) - pos
		if maxLength > 255 {
			maxLength = 255
		}

		for length < maxLength {
			currentPos := pos + length
			matchPos := candidate + length

			if currentPos >= len(data) || matchPos >= pos {
				break
			}

			if data[currentPos] == data[matchPos] {
				length++
			} else {
				break
			}
		}

		if length >= 3 && length > bestLength {
			bestLength = length
			bestDistance = distance
		}
	}

	return Match{length: bestLength, distance: bestDistance}
}

func (lzma *LzmaCompressor) encodeLiteral(writer *bytes.Buffer, literal byte) {
	writer.WriteByte(literal)
}

func (lzma *LzmaCompressor) encodeMatch(writer *bytes.Buffer, length int, distance int) {
	controlByte := byte(0x80)
	writer.WriteByte(controlByte)

	lengthByte := byte(length - 3)
	writer.WriteByte(lengthByte)

	distanceBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(distanceBytes, uint16(distance))
	writer.Write(distanceBytes)
}

func (lzma *LzmaCompressor) buildHashTable(data []byte) {
	lzma.hashTable = make(map[uint32][]int)
	for i := 0; i <= len(data)-3; i++ {
		hash := lzma.computeHash(data, i)
		lzma.hashTable[hash] = append(lzma.hashTable[hash], i)
	}
}

func (lzma *LzmaCompressor) computeHash(data []byte, pos int) uint32 {
	if pos+2 >= len(data) {
		return 0
	}
	return uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16
}

func (lzma *LzmaCompressor) validateInput(data []byte) error {
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

func (lzma *LzmaCompressor) CompressWithValidation(data []byte) ([]byte, error) {
	err := lzma.validateInput(data)
	if err != nil {
		return nil, err
	}

	return lzma.Compress(data)
}

func (lzma *LzmaCompressor) DecompressWithValidation(data []byte) ([]byte, error) {
	err := lzma.validateInput(data)
	if err != nil {
		return nil, err
	}

	return lzma.Decompress(data)
}

func (lzma *LzmaCompressor) GetCompressionRatio(original, compressed []byte) float64 {
	if len(original) == 0 {
		return 0.0
	}
	return float64(len(compressed)) / float64(len(original))
}
