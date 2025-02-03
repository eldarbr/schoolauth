package stages

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

type RequiredActionResult struct {
	code string
}

const (
	requiredActionURL = "https://auth.sberclass.ru/auth/realms/EduPowerKeycloak/login-actions/required-action"
)

func RequiredAction(ctx context.Context, authenticate AuthenticateResult) (RequiredActionResult, error) {
	result := RequiredActionResult{}
	client := http.Client{
		CheckRedirect: createCheckRedirectRequiredAction(&result),
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requiredActionURL, nil)
	if err != nil {
		return RequiredActionResult{}, fmt.Errorf("new request: %w", err)
	}

	request.AddCookie(&http.Cookie{Name: "AUTH_SESSION_ID", Value: authenticate.authSessionID})
	request.AddCookie(&http.Cookie{Name: "AUTH_SESSION_ID_LEGACY", Value: authenticate.authSessionID})
	request.AddCookie(&http.Cookie{Name: "KC_RESTART", Value: authenticate.kcRestart})

	query := request.URL.Query()

	query.Set(executionTag, "EDU_CONSISTENCY_CHECK")
	query.Set("client_id", "school21")
	query.Set(tabIDtag, authenticate.tabID)

	request.URL.RawQuery = query.Encode()

	resp, err := client.Do(request)
	if err != nil {
		return RequiredActionResult{}, fmt.Errorf("do request: %w", err)
	}

	defer resp.Body.Close()

	if result.code == "" { // no redirect
		return RequiredActionResult{}, ErrWrongRedirect
	}

	return result, nil
}

func createCheckRedirectRequiredAction(res *RequiredActionResult) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, _ []*http.Request) error {
		query, err := url.ParseQuery(req.URL.Fragment)
		if err != nil {
			return fmt.Errorf("parse fragment query: %w", err)
		}

		if !query.Has("code") {
			return ErrWrongRedirect
		}

		res.code = query.Get("code")

		return http.ErrUseLastResponse
	}
}
