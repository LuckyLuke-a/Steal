package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/curve25519"
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


func Encrypt(plainText, key, nonce []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
	aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    cipherText := aesGCM.Seal(nil, nonce, plainText, nil)
    return cipherText, nil
}



func Decrypt(cipherText, key, nonce []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
    if err != nil {
        return nil, err
    }
    return plainText, nil
}


