package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/eldarbr/schoolauth/internal/token"
)

type tokenResponseModel struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

const (
	tokenURL = "https://auth.sberclass.ru/auth/realms/EduPowerKeycloak/protocol/openid-connect/token"
)

func Token(ctx context.Context, requiredAction RequiredActionResult) (token.Token, error) {
	reqBody := url.Values{}
	reqBody.Set("code", requiredAction.code)
	reqBody.Set("grant_type", "authorization_code")
	reqBody.Set("client_id", "school21")
	reqBody.Set("redirect_uri", "https://edu.21-school.ru/")

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(reqBody.Encode()))
	if err != nil {
		return token.Token{}, fmt.Errorf("new request: %w", err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return token.Token{}, fmt.Errorf("do request: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return token.Token{}, fmt.Errorf("wrong status code: %d", response.StatusCode)
	}

	parsedResponse := tokenResponseModel{}

	err = json.NewDecoder(response.Body).Decode(&parsedResponse)
	if err != nil {
		return token.Token{}, fmt.Errorf("decode resp body: %w", err)
	}

	return token.NewToken(
		parsedResponse.AccessToken,
		time.Now().Unix()+int64(parsedResponse.ExpiresIn),
	), nil
}
