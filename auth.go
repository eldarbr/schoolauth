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

	authenticateRes, err := stages.Authenticate(ctx, preauthRes, username, password)
	if err != nil {
		return token.Token{}, fmt.Errorf("authenticate: %w", err)
	}

	requiredActionRes, err := stages.RequiredAction(ctx, authenticateRes)
	if err != nil {
		return token.Token{}, fmt.Errorf("requiredAction: %w", err)
	}

	tokenRes, err := stages.Token(ctx, requiredActionRes)
	if err != nil {
		return token.Token{}, fmt.Errorf("token: %w", err)
	}

	return tokenRes, nil
}
