package KeyTools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/corvus-ch/shamir"
	TCFSTypes "serverTCFS/types"
)

// GenerateKey Generate a AES 256 key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SplitKey splits a key using Shamir's secret sharing
func SplitKey(key []byte, n int, k int) (map[byte][]byte, error) {
	shares, err := shamir.Split(key, n, k)
	if err != nil {
		return nil, err
	}
	return shares, nil
}

// parsePublicKeyFromPEMString Returns an rsa key froma pem string in PKIX format
func parsePublicKeyFromPEMString(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not RSA")
	}

	return rsaPub, nil
}

// EncryptKeyPart Encrypts a keypart from shamir alg. with a public key
func EncryptKeyPart(keyPart []byte, publicKey string) (string, error) {
	// Parse the public key
	pubKeyToRSA, err := parsePublicKeyFromPEMString(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse string to rsa key: %w", err)
	}

	// Encrypt the key part using RSA-OAEP with SHA-256 hash function
	label := []byte("")
	hash := sha256.New()
	encryptedKeyPart, err := rsa.EncryptOAEP(hash, rand.Reader, pubKeyToRSA, keyPart, label)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt key part: %w", err)
	}

	return hex.EncodeToString(encryptedKeyPart), nil
}

// EncryptSharesForSharedFile Encrypts all the keyparts from a slice of SharedFile structs
func EncryptSharesForSharedFile(sharedFile *TCFSTypes.SharedFile) error {
	encryptedShare, err := EncryptKeyPart(sharedFile.Share, sharedFile.User.PublicKey)
	if err != nil {
		return err
	}
	sharedFile.EncryptedShare = encryptedShare
	return nil
}

// EncryptSharesForSharedFileList same as EncryptSharesForSharedFile but works with slices
func EncryptSharesForSharedFileList(list *[]TCFSTypes.SharedFile) error {
	for i := range *list {
		fmt.Printf("Encrypting share for %v\n", (*list)[i].User.Username)
		err := EncryptSharesForSharedFile(&(*list)[i])
		if err != nil {
			return err
		}
	}
	return nil
}
