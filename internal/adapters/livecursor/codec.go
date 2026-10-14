package livecursor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/JustIkra/umir-gateway/internal/journal"
)

type Codec struct{ cipher cipher.AEAD }

func New(secret string) (*Codec, error) {
	if secret == "" {
		return nil, errors.New("live cursor: secret is required")
	}
	key := sha256.Sum256([]byte("umir-gateway/live-cursor/v1\x00" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Codec{cipher: aead}, nil
}

func (c *Codec) Encode(position journal.CursorPosition) (string, error) {
	data, err := json.Marshal(position)
	if err != nil {
		return "", err
	}
	if len(data) > 512 {
		return "", errors.New("live cursor: position too large")
	}
	nonce := make([]byte, c.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := c.cipher.Seal(nonce, nonce, data, []byte("umir-live-v1"))
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (c *Codec) Decode(handle string) (journal.CursorPosition, error) {
	if len(handle) > 1024 {
		return journal.CursorPosition{}, journal.ErrCursor
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(handle)
	if err != nil || len(data) <= c.cipher.NonceSize()+c.cipher.Overhead() || len(data) > 540 {
		return journal.CursorPosition{}, journal.ErrCursor
	}
	nonce := data[:c.cipher.NonceSize()]
	plaintext, err := c.cipher.Open(nil, nonce, data[c.cipher.NonceSize():], []byte("umir-live-v1"))
	if err != nil {
		return journal.CursorPosition{}, journal.ErrCursor
	}
	var position journal.CursorPosition
	if err := json.Unmarshal(plaintext, &position); err != nil || position.Sequence < 1 || position.Generation == 0 || position.Tenant == "" || position.Actor == "" || position.Epoch == "" || position.Expires.IsZero() {
		return journal.CursorPosition{}, journal.ErrCursor
	}
	return position, nil
}
