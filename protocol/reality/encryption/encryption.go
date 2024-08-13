package encryption

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
	"golang.org/x/crypto/curve25519"

	mathRand "math/rand"
	cryptoRand "crypto/rand"

)



func GenerateAuthKey(random []byte, intervalSecond int64, secretKey string, timeCounter int64) (publicKey, privateKey []byte, err error) {
	if timeCounter == 0{
		timeCounter = time.Now().UTC().Unix() / intervalSecond
	}
	timeCounterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeCounterBytes, uint64(timeCounter))

	hmacHash := hmac.New(sha256.New, []byte(secretKey))
	_, err = hmacHash.Write(timeCounterBytes)
	if err != nil{
		return
	}
	_, err = hmacHash.Write(random[:10])
	if err != nil{
		return
	}

	hash := hmacHash.Sum(nil)

	privateKey = hash[:32]
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil{
		return 
	}
	return 
}



func GenerateSessionId(random, authKey []byte) []byte {
	hmacHash := hmac.New(sha512.New, authKey)
	_, err := hmacHash.Write(random[10:16])
	if err != nil{
		return nil
	}
	hash := hmacHash.Sum(nil)
	return hash[:32]
}



func ValidateSessionId(random, sessionId, publicKey []byte, inervalSecond, skewSecond int64, secretKey string) ([]byte, error) {
	timeCounter := time.Now().UTC().Unix() / inervalSecond
	var i int64 = 0

	for ; i >= -skewSecond ; i-- {
		_, privateKey, err := GenerateAuthKey(random, inervalSecond, secretKey, timeCounter+i)
		if err != nil{
			continue
		}
		authKey, err := curve25519.X25519(privateKey, publicKey)
		if err != nil{
			continue
		}

		generateSession := GenerateSessionId(random, authKey)
		if generateSession == nil{
			continue
		}
		if bytes.Equal(generateSession, sessionId){
			return authKey, nil
		}
	}
	return nil, fmt.Errorf("failed to validate session id")
}



func AddPadding(data []byte, minSplitSize, maxSplitSize, paddingSize, subChunkSize int) [][]byte{
	var chunks [][]byte

	for len(data) > 0 {
		chunkSize := mathRand.Intn(maxSplitSize-minSplitSize+1) + minSplitSize
		if chunkSize > len(data) {
			chunkSize = len(data)
		}

		// Split the data into a chunk
		chunk := data[:chunkSize]
		data = data[chunkSize:]

		paddedChunk := addRandomPaddingAndSplit(chunk, paddingSize, subChunkSize)

		// Add the padded chunk to the list
		chunks = append(chunks, paddedChunk)
	}

	return chunks
}


func RemovePadding(chunks [][]byte, paddingSize, subChunkSize int) []byte {
	var result []byte
	for _, chunk := range chunks {
		originalChunk := removePaddingAndMerge(chunk, paddingSize, subChunkSize)
		result = append(result, originalChunk...)
	}
	return result

}



func addRandomPaddingAndSplit(chunk []byte, paddingSize, subChunkSize int) []byte {
	var paddedChunk []byte
	for len(chunk) > 0 {
		if subChunkSize > len(chunk) {
			subChunkSize = len(chunk)
		}
		subChunk := chunk[:subChunkSize]
		chunk = chunk[subChunkSize:]

		getPadding := make([]byte, paddingSize)
		for i := range getPadding {
			// Generate a random byte between 32 and 126 (inclusive)
			randomByte, _ := cryptoRand.Int(cryptoRand.Reader, big.NewInt(95)) // 126 - 32 + 1 = 95
			getPadding[i] = byte(randomByte.Int64() + 32)
		}
		paddedChunk = append(paddedChunk, getPadding...)
		paddedChunk = append(paddedChunk, subChunk...)
	}

	return paddedChunk
}



func removePaddingAndMerge(paddedChunk []byte, paddingSize, subChunkSize int) []byte {
	var originalChunk []byte

	for {
		if len(paddedChunk) <= paddingSize {
			break // No more data left, just padding
		}

		// Skip padding
		paddedChunk = paddedChunk[paddingSize:]

		// Extract the sub-chunk
		if len(paddedChunk) < subChunkSize {
			subChunkSize = len(paddedChunk)
		}
		subChunk := paddedChunk[:subChunkSize]
		originalChunk = append(originalChunk, subChunk...)

		// Remove the sub-chunk from paddedChunk
		paddedChunk = paddedChunk[subChunkSize:]
	}

	return originalChunk
}



func generateRandomBytes(key, input []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(input)
	return h.Sum(nil)
}

func adjustByteRange(b byte) byte {
	return 32 + (b % (126 - 32 + 1))
}

func GenerateRandomPacket(sharedKey []byte, timeInterval int64, packetLength int) []byte{
	timestamp := time.Now().Unix() / timeInterval
	inputData := make([]byte, 8)
	binary.BigEndian.PutUint64(inputData, uint64(timestamp))

	var randomBytes []byte
	blocksNeeded := (packetLength + 31) / 32 // Calculate the number of 32-byte blocks needed

	for i := 0; i < blocksNeeded; i++ {
		counter := make([]byte, 4)
		binary.BigEndian.PutUint32(counter, uint32(i))
		hmacBytes := generateRandomBytes(sharedKey, append(inputData, counter...))

		// Adjust each byte to be in the range [32, 126]
		for _, b := range hmacBytes {
			randomBytes = append(randomBytes, adjustByteRange(b))
		}
	}

	// Truncate to the required packet length
	return randomBytes[:packetLength]
}