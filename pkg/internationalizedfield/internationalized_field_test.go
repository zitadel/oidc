package internationalizedfield

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	"testing"
)

func TestInternationalizedField_UnmarshalJSON(t *testing.T) {
	wantJPTag, err := language.Parse("ja-Jpan-JP")
	require.NoError(t, err)
	t.Run("unmarshal valid JSON", func(t *testing.T) {
		marshalled1 := []byte(`
{
	"client_name": "My Example",
	"client_name#ja-Jpan-JP": "クライアント名"
}
`)
		req1 := New("client_name")
		require.NoError(t, json.Unmarshal(marshalled1, &req1))

		require.Len(t, req1.Items, 2)
		assert.Contains(t, req1.Items, language.Und)
		assert.Contains(t, req1.Items, wantJPTag)

		assert.Equal(t, "My Example", req1.Items[language.Und])
		assert.Equal(t, "クライアント名", req1.Items[wantJPTag])
	})
	t.Run("unmarshal valid JSON with missing field", func(t *testing.T) {
		marshalled1 := []byte(`
{
	"hello": "world"
}
`)
		req1 := New("client_name")
		require.NoError(t, json.Unmarshal(marshalled1, &req1))

		require.Empty(t, req1.Items)
	})
	t.Run("unmarshal JSON with invalid tag", func(t *testing.T) {
		require.NoError(t, err)

		marshalled1 := []byte(`
{
	"client_name": "My Example",
	"client_name#invalid_tag": "hello world",
}
`)
		req1 := New("client_name")
		require.Error(t, json.Unmarshal(marshalled1, &req1))
	})
}

func TestInternationalizedField_MarshalJSON(t *testing.T) {
	wantJPTag, err := language.Parse("ja-Jpan-JP")
	require.NoError(t, err)
	t.Run("marshal valid JSON", func(t *testing.T) {
		want := []byte(`
{
	"client_name": "My Example",
	"client_name#ja-Jpan-JP": "クライアント名"
}
`)
		req := New("client_name")
		req.Items[language.Und] = "My Example"
		req.Items[wantJPTag] = "クライアント名"

		marshalled, err := json.Marshal(req)
		require.NoError(t, err)

		assert.JSONEq(t, string(marshalled), string(want))
	})
	t.Run("marshal empty JSON", func(t *testing.T) {
		req := New("client_name")

		marshalled, err := json.Marshal(req)
		require.NoError(t, err)

		assert.JSONEq(t, string(marshalled), `{}`)
	})
}
