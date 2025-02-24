package schoolauth_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/eldarbr/schoolauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	envLogin    = "TEST_LOGIN"
	envPassword = "TEST_PASSWORD"
)

var (
	login    string
	password string
)

func TestMain(t *testing.M) {
	login = os.Getenv(envLogin)
	password = os.Getenv(envPassword)

	t.Run()
}

func TestManagedTmpCreate(t *testing.T) {
	t.Parallel()

	if login == "" || password == "" {
		t.Skip("login or password not set")
	}

	managed := schoolauth.NewManagedToken(login, password, nil)

	token, err := managed.Get(context.Background())
	require.NoError(t, err)

	assert.NotEmpty(t, token)

	require.NoError(t, managed.Invalidate())
}

func TestManagedCreateRestore(t *testing.T) {
	t.Parallel()

	if login == "" || password == "" {
		t.Skip("login or password not set")
	}

	tmpfile, err := os.CreateTemp("", "")
	require.NoError(t, err)

	require.NoError(t, tmpfile.Close())

	tmpfileName := tmpfile.Name()

	{
		managed := schoolauth.NewManagedToken(login, password, &tmpfileName)

		token, err := managed.Get(context.Background())
		require.NoError(t, err)

		assert.NotEmpty(t, token)
	}

	{
		start := time.Now().UnixMilli()

		managed := schoolauth.NewManagedToken(login, password, &tmpfileName)

		token, err := managed.Get(context.Background())
		require.NoError(t, err)

		diff := time.Now().UnixMilli() - start

		assert.NotEmpty(t, token)
		assert.Less(t, diff, int64(100))
	}

	os.Remove(tmpfileName)
}
