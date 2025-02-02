package stages

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

type PreauthResult struct {
	authSessionID string
	kcRestart     string
	nonce         string
	tabID         string
	sessionCode   string
	execution     string
}

const (
	defaultPreauthRedirect = "https://edu.21-school.ru/"
	preauthURL             = "https://auth.sberclass.ru/auth/realms/EduPowerKeycloak/protocol/openid-connect/auth"
)

var (
	ErrParseSetCookie       = errors.New("parse set cookie headers: incomplete result")
	ErrParseBodyQueryParams = errors.New("body query params were wrong")

	preauthRegexpBodyData = regexp.MustCompile(`(https[:/.=&;\w\-\?]+)"`)
)

func Preauth(ctx context.Context) (PreauthResult, error) {
	state := uuid.NewString()
	nonce := uuid.NewString()
	result := PreauthResult{
		nonce: nonce,
	}

	resp, err := doPreauthRequest(ctx, nonce, state)
	if err != nil {
		return PreauthResult{}, fmt.Errorf("do preauth request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PreauthResult{}, fmt.Errorf("request status code: %d", resp.StatusCode)
	}

	err = parsePreauthBody(&result, resp.Body)
	if err != nil {
		return PreauthResult{}, fmt.Errorf("parse body: %w", err)
	}

	for _, setCookieValue := range resp.Header.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(setCookieValue)
		if err != nil {
			log.Printf("parse set cookie %s: %s", setCookieValue, err.Error())

			continue
		}

		switch cookie.Name {
		case "AUTH_SESSION_ID":
			result.authSessionID = cookie.Value
		case "KC_RESTART":
			result.kcRestart = cookie.Value
		}
	}

	if result.authSessionID == "" || result.kcRestart == "" {
		return PreauthResult{}, ErrParseSetCookie
	}

	return result, nil
}

func doPreauthRequest(ctx context.Context, nonce, state string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, preauthURL, nil)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	query := request.URL.Query()

	query.Add("client_id", "school21")
	query.Add("redirect_uri", defaultPreauthRedirect)
	query.Add("state", state)
	query.Add("response_mode", "fragment")
	query.Add("response_type", "code")
	query.Add("scope", "openid")
	query.Add("nonce", nonce)

	request.URL.RawQuery = query.Encode()

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return resp, fmt.Errorf("default client preauth: %w", err)
	}

	return resp, nil
}

func parsePreauthBody(placeholder *PreauthResult, body io.Reader) error {
	const (
		tabIDtag       = "tab_id"
		sessionCodeTag = "execution"
		executionTag   = "session_code"
	)

	reader := bufio.NewReader(body)
	match := [][]byte(nil)

	for match == nil {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		match = preauthRegexpBodyData.FindSubmatch(line)
	}

	bodyURL := strings.ReplaceAll(string(match[1]), "amp;", "")

	parsedURL, err := url.Parse(bodyURL)
	if err != nil {
		return fmt.Errorf("parse url from the body \"%s\": %w", bodyURL, err)
	}

	query, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return fmt.Errorf("parse url query from the body \"%s\": %w", parsedURL.RawQuery, err)
	}

	if len(query[tabIDtag]) != 1 || len(query[sessionCodeTag]) != 1 || len(query[executionTag]) != 1 {
		return ErrParseBodyQueryParams
	}

	placeholder.tabID = query[tabIDtag][0]
	placeholder.sessionCode = query[sessionCodeTag][0]
	placeholder.execution = query[executionTag][0]

	return nil
}
