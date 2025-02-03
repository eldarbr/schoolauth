package token

import (
	"errors"
	"time"
)

var (
	ErrTokenExpired = errors.New("the token is expired, get a new one")
	ErrNoToken      = errors.New("no token")
)

type Token struct {
	authToken string
	expires   int64
}

func NewToken(tok string, exp int64) Token {
	return Token{authToken: tok, expires: exp}
}

func (t Token) GetAuthToken() (string, error) {
	if t.authToken == "" {
		return "", ErrNoToken
	}

	if time.Now().Unix() >= t.expires {
		return "", ErrTokenExpired
	}

	return t.authToken, nil
}
