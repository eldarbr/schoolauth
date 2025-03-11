package schoolauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/eldarbr/schoolauth/internal/token"
	"golang.org/x/crypto/pbkdf2"
)

type ManagedToken struct {
	username string
	password string
	savePath string
	loaded   *token.Token
}

const (
	tmpfileName = "21auth.bin"
)

var ErrShortCiphertext = errors.New("ciphertext too short")

func NewManagedToken(username, password string, savePath *string) *ManagedToken {
	var path string

	if savePath != nil {
		path = *savePath
	} else {
		path = filepath.Join(os.TempDir(), tmpfileName)
	}

	return &ManagedToken{
		username: username,
		password: password,
		savePath: path,
		loaded:   nil,
	}
}

func (tok *ManagedToken) Invalidate() error {
	_, err := os.Stat(tok.savePath)
	if err != nil {
		return nil //nolint:nilerr // file does not exist.
	}

	err = os.Remove(tok.savePath)
	if err != nil {
		return fmt.Errorf("remove saved file: %w", err)
	}

	return nil
}

func (tok *ManagedToken) Get(ctx context.Context) (string, error) {
	var (
		token string
		err   error
	)

	if tok.loaded != nil {
		token, err = tok.loaded.GetAuthToken()
		if err == nil {
			return token, nil
		}
	}

	fileContent, err := ReadFromFile(tok.savePath)
	if err == nil {
		token, err = tok.tryDecrypt(fileContent)
		if err == nil {
			return token, nil
		}
	}

	token, err = tok.saveNewToken(ctx)
	if err != nil {
		return "", fmt.Errorf("save new token: %w", err)
	}

	return token, nil
}

func (tok *ManagedToken) tryDecrypt(encrypted []byte) (string, error) {
	tokenSerialized, err := Decrypt(encrypted, tok.username+tok.password)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	token, err := DeserializeStruct(tokenSerialized)
	if err != nil {
		return "", fmt.Errorf("deserialize: %w", err)
	}

	authToken, err := token.GetAuthToken()
	if err != nil {
		return "", fmt.Errorf("get decrypted token: %w", err)
	}

	tok.loaded = &token

	return authToken, nil
}

func (tok *ManagedToken) saveNewToken(ctx context.Context) (string, error) {
	var (
		token      token.Token
		serialized []byte
		err        error
	)

	token, err = Auth(ctx, tok.username, tok.password)
	if err != nil {
		return "", fmt.Errorf("new auth: %w", err)
	}

	authToken, err := token.GetAuthToken()
	if err != nil {
		return "", fmt.Errorf("get auth token: %w", err)
	}

	serialized, err = SerializeToken(token)
	if err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}

	serialized, err = Encrypt(serialized, tok.username+tok.password)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}

	err = SaveToFile(tok.savePath, serialized)
	if err != nil {
		return "", fmt.Errorf("save to file: %w", err)
	}

	tok.loaded = &token

	return authToken, nil
}

// DeriveKey generates a 32-byte AES key from a password using PBKDF2.
func DeriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 4096, 32, sha256.New)
}

func SerializeToken(data token.Token) ([]byte, error) {
	buf := bytes.Buffer{}
	encoder := gob.NewEncoder(&buf)

	err := encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("encode token: %w", err)
	}

	return buf.Bytes(), nil
}

func DeserializeStruct(data []byte) (token.Token, error) {
	result := token.Token{}
	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)

	err := decoder.Decode(&result)
	if err != nil {
		return result, fmt.Errorf("decode token: %w", err)
	}

	return result, nil
}

// Encrypt encrypts binary data using AES-GCM with a password.
func Encrypt(data []byte, password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("create salt: %w", err)
	}

	key := DeriveKey(password, salt)

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("create nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, data, nil)

	result := bytes.Buffer{}
	result.Write(salt)
	result.Write(nonce)
	result.Write(ciphertext)

	return result.Bytes(), nil
}

// Decrypt decrypts binary data using AES-GCM with a password.
func Decrypt(encryptedData []byte, password string) ([]byte, error) {
	if len(encryptedData) < 16+12 {
		return nil, ErrShortCiphertext
	}

	salt := encryptedData[:16]
	nonce := encryptedData[16:28]
	ciphertext := encryptedData[28:]

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}

	return plaintext, nil
}

// SaveToFile writes encrypted data to a file.
func SaveToFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

// ReadFromFile reads encrypted data from a file.
func ReadFromFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
