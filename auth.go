package schoolauth

import (
	"context"
	"fmt"

	"github.com/eldarbr/schoolauth/internal/stages"
	"github.com/eldarbr/schoolauth/internal/token"
)

func Auth(ctx context.Context, username, password string) (token.Token, error) {
	preauthRes, err := stages.Preauth(ctx)
	if err != nil {
		return token.Token{}, fmt.Errorf("preauth: %w", err)
	}

	_ = preauthRes

	return token.Token{}, nil
}
