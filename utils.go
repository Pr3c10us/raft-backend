package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	stdRand "math/rand"
	"path/filepath"
	"strings"
	"time"
)

// deriveMasterKey uses PBKDF2 to derive a 32-byte master key from a passphrase and salt.
func deriveMasterKey(passphrase, salt string) []byte {
	// Increase iteration count for production usage.
	masterKey := pbkdf2.Key([]byte(passphrase), []byte(salt), 10000, 32, sha256.New)
	return masterKey
}

// splitKey splits a 32-byte master key into two 16-byte subkeys.
func splitKey(masterKey []byte) (encKey, macKey []byte) {
	if len(masterKey) < 32 {
		panic("master key must be at least 32 bytes")
	}
	encKey = masterKey[:16]
	macKey = masterKey[16:32]
	return
}

// encrypt encrypts plaintext using AES-GCM.
func encrypt(plaintext string, encKey []byte) (string, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("new cipher error: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new GCM error: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce creation error: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts a base64-encoded AES-GCM ciphertext using encKey.
func decrypt(ciphertextB64 string, encKey []byte) (string, error) {
	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode error: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("new cipher error: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("new GCM error: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(decodedCiphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := decodedCiphertext[:nonceSize], decodedCiphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("gcm open error: %w", err)
	}
	return string(plaintext), nil
}

// sign generates an HMAC-SHA256 signature over data using macKey.
func sign(data string, macKey []byte) string {
	h := hmac.New(sha256.New, macKey)
	_, _ = h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// validateSignature verifies the HMAC signature for data using macKey.
func validateSignature(data, signature string, macKey []byte) bool {
	expectedSignature := sign(data, macKey)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func sanitizeFilename(name string) string {
	if name == "" {
		return ""
	}
	if strings.Contains(name, "..") ||
		strings.HasPrefix(name, "/") ||
		strings.HasPrefix(name, "\\") ||
		strings.ContainsAny(name, `:*?"<>|`) {
		return ""
	}
	return filepath.Clean(name)
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(nBig.Int64())
}

func init() {
	// Seed the math/rand for any random usage (non-crypto).
	stdRand.Seed(time.Now().UnixNano())
}

func GenerateSecureRandomString() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 10)
	for i := range result {
		b, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[b.Int64()]
	}
	return string(result)
}
