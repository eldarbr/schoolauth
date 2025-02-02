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

func (t Token) GetAuthToken() (string, error) {
	if t.authToken == "" {
		return "", ErrNoToken
	}

	if time.Now().Unix() >= t.expires {
		return "", ErrTokenExpired
	}

	return t.authToken, nil
}
