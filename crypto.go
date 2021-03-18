package ledger

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"github.com/pkg/errors"

	"github.com/btcsuite/btcutil/base58"
	
	"golang.org/x/crypto/blake2b"
)

//
// Original Source: crypto.go
// https://github.com/goat-systems/go-tezos/blob/master/internal/crypto/crypto.go
//

type Prefix []byte

//B58cencode encodes a byte array into base58 with prefix
func B58cencode(payload []byte, prefix Prefix) string {
	n := make([]byte, (len(prefix) + len(payload)))
	for k := range prefix {
		n[k] = prefix[k]
	}
	for l := range payload {
		n[l+len(prefix)] = payload[l]
	}
	b58c := encode(n)
	return b58c
}

func B58cdecode(payload string, prefix []byte) []byte {
	b58c, _ := decode(payload)
	return b58c[len(prefix):]
}

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func encode(dataBytes []byte) string {

	// Performing SHA256 twice
//	sha256hash := sha256.New()
//	sha256hash.Write(dataBytes)
//	middleHash := sha256hash.Sum(nil)
//	sha256hash = sha256.New()
//	sha256hash.Write(middleHash)
//	hash := sha256hash.Sum(nil)

	h := sha256.Sum256(dataBytes)
	hash := sha256.Sum256(h[:])

	checksum := hash[:4]
	dataBytes = append(dataBytes, checksum...)

	// For all the "00" versions or any prepended zeros as base58 removes them
	zeroCount := 0
	for _, b := range dataBytes {
		if b == 0 {
			zeroCount++
		} else {
			break
		}
	}

	// Performing base58 encoding
	encoded := base58.Encode(dataBytes)

	for i := 0; i < zeroCount; i++ {
		encoded = "1" + encoded
	}

	return encoded
}

func decode(encoded string) ([]byte, error) {
	zeroCount := 0
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == 49 {
			zeroCount++
		} else {
			break
		}
	}

	dataBytes, err := b58decode(encoded)
	if err != nil {
		return []byte{}, err
	}

	if len(dataBytes) <= 4 {
		return []byte{}, errors.New("invalid decode length")
	}
	data, checksum := dataBytes[:len(dataBytes)-4], dataBytes[len(dataBytes)-4:]

	for i := 0; i < zeroCount; i++ {
		data = append([]byte{0}, data...)
	}

	// Performing SHA256 twice to validate checksum
//	sha256hash := sha256.New()
//	sha256hash.Write(data)
//	middleHash := sha256hash.Sum(nil)
//	sha256hash = sha256.New()
//	sha256hash.Write(middleHash)
//	hash := sha256hash.Sum(nil)

	h := sha256.Sum256(data)
	hash := sha256.Sum256(h[:])

	if !bytes.Equal(checksum, hash[:4]) {
		return []byte{}, errors.New("data and checksum don't match")
	}

	return data, nil
}

func b58decode(data string) ([]byte, error) {
	decimalData := new(big.Int)
	alphabetBytes := []byte(alphabet)
	multiplier := big.NewInt(58)

	for _, value := range data {
		pos := bytes.IndexByte(alphabetBytes, byte(value))
		if pos == -1 {
			return nil, errors.New("character not found in alphabet")
		}
		decimalData.Mul(decimalData, multiplier)
		decimalData.Add(decimalData, big.NewInt(int64(pos)))
	}

	return decimalData.Bytes(), nil
}

func Blake2b(bufferBytes []byte, size int) ([]byte, error) {

	// Generic hash of bytes
    bufferBytesHashGen, err := blake2b.New(size, []byte{})
    if err != nil {
        return []byte{0}, errors.Wrap(err, "Unable create blake2b hash object")
    }

    // Write buffer bytes to hash
    _, err = bufferBytesHashGen.Write(bufferBytes)
    if err != nil {
        return []byte{0}, errors.Wrap(err, "Unable write buffer bytes to hash function")
    }

    // Generate checksum of buffer bytes
    bufferHash := bufferBytesHashGen.Sum([]byte{})

	return bufferHash, nil
}
