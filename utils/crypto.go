package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// generateKey derives a 32-byte key using Argon2id
// The passphrase will be a combination of ParentPassword and the current TOTP Code
func generateKey(passphrase, salt string) []byte {
	// Argon2id parameters
	time := uint32(1)
	memory := uint32(64 * 1024)
	threads := uint8(4)
	keyLen := uint32(32)

	// In a real application, a proper random salt should be used per entry or user.
	// We'll use the provided salt (e.g., username or fixed salt) to make it deterministic
	// since we don't store the salt per password entry at the moment, but ideally we should.
	// For simplicity, we use the provided salt.
	return argon2.IDKey([]byte(passphrase), []byte(salt), time, memory, threads, keyLen)
}

// Encrypt encrypts plaintext using AES-256-GCM
// Passphrase should be the user's Parent Password + TOTP sequence
func Encrypt(plaintext, passphrase, salt string) (string, error) {
	key := generateKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Prepend the nonce to the ciphertext
	finalData := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(finalData), nil
}

// Decrypt decrypts an AES-256-GCM base64 encoded string
func Decrypt(encodedCiphertext, passphrase, salt string) (string, error) {
	key := generateKey(passphrase, salt)

	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", err
	}

	if len(data) < 12 {
		return "", errors.New("ciphertext too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("incorrect parent password or TOTP code")
	}

	return string(plaintext), nil
}
