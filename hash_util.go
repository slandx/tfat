package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/argon2"
	"io"
	"log"
	"strings"
)

const (
	PwSaltLength = 32
	PwLength     = 64
)

func getSalt() ([]byte, error) {
	salt := make([]byte, PwSaltLength/2)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

func hashPassword(password string) (hashedKey string, saltStr string) {
	salt, err := getSalt()
	if err != nil {
		log.Fatal("Hash password failed")
	}
	key := argon2.Key([]byte(password), salt, 3, 32*1024, 4, 32)
	return strings.ToUpper(hex.EncodeToString(key)), strings.ToUpper(hex.EncodeToString(salt))
}

func verifyPassword(plainPwd string, hexSalt string, hexHashStr string) bool {
	salt, err := hex.DecodeString(hexSalt)
	if err != nil {
		log.Fatal("Decode salt failed")
	}
	hash, err := hex.DecodeString(hexHashStr)
	if err != nil {
		log.Fatal("Decode hash string failed")
	}
	key := argon2.Key([]byte(plainPwd), salt, 3, 32*1024, 4, 32)
	return bytes.Equal(key, hash)
}
