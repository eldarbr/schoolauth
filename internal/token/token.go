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
	AuthToken string
	Expires   int64
}

func NewToken(tok string, exp int64) Token {
	return Token{AuthToken: tok, Expires: exp}
}

func (t Token) GetAuthToken() (string, error) {
	if t.AuthToken == "" {
		return "", ErrNoToken
	}

	if time.Now().Unix() >= t.Expires {
		return "", ErrTokenExpired
	}

	return t.AuthToken, nil
}
