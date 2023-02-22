package op

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	mr "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type errReader struct {
}

func (errReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func runWithRandReader(r io.Reader, f func()) {
	originalReader := rand.Reader
	rand.Reader = r
	defer func() {
		rand.Reader = originalReader
	}()

	f()
}

func TestNewDeviceCode(t *testing.T) {
	t.Run("reader error", func(t *testing.T) {
		runWithRandReader(errReader{}, func() {
			_, err := NewDeviceCode(16)
			require.Error(t, err)
		})
	})

	t.Run("dirrent lengths, rand reader", func(t *testing.T) {
		for i := 1; i <= 32; i++ {
			got, err := NewDeviceCode(i)
			require.NoError(t, err)
			assert.Len(t, got, base64.RawURLEncoding.EncodedLen(i))
		}
	})

}

func TestNewUserCode(t *testing.T) {
	type args struct {
		charset      []rune
		charAmount   int
		dashInterval int
	}
	tests := []struct {
		name    string
		args    args
		reader  io.Reader
		want    string
		wantErr bool
	}{
		{
			name: "reader error",
			args: args{
				charset:      []rune(CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader:  errReader{},
			wantErr: true,
		},
		{
			name: "base20",
			args: args{
				charset:      []rune(CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "XKCD-HTTD",
		},
		{
			name: "digits",
			args: args{
				charset:      []rune(CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "271-256-225",
		},
		{
			name: "no dashes",
			args: args{
				charset:    []rune(CharSetDigits),
				charAmount: 9,
			},
			reader: mr.New(mr.NewSource(1)),
			want:   "271256225",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runWithRandReader(tt.reader, func() {
				got, err := NewUserCode(tt.args.charset, tt.args.charAmount, tt.args.dashInterval)
				if tt.wantErr {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, tt.want, got)
			})

		})
	}

	t.Run("crypto/rand", func(t *testing.T) {
		const testN = 100000

		for _, c := range []UserCodeConfig{UserCodeBase20, UserCodeDigits} {
			t.Run(c.CharSet, func(t *testing.T) {
				results := make(map[string]int)

				for i := 0; i < testN; i++ {
					code, err := NewUserCode([]rune(c.CharSet), c.CharAmount, c.DashInterval)
					require.NoError(t, err)
					results[code]++
				}

				t.Log(results)

				var duplicates int
				for code, count := range results {
					assert.Less(t, count, 3, code)
					if count == 2 {
						duplicates++
					}
				}

			})
		}
	})
}

func BenchmarkNewUserCode(b *testing.B) {
	type args struct {
		charset      []rune
		charAmount   int
		dashInterval int
	}
	tests := []struct {
		name   string
		args   args
		reader io.Reader
	}{
		{
			name: "math rand, base20",
			args: args{
				charset:      []rune(CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: mr.New(mr.NewSource(1)),
		},
		{
			name: "math rand, digits",
			args: args{
				charset:      []rune(CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: mr.New(mr.NewSource(1)),
		},
		{
			name: "crypto rand, base20",
			args: args{
				charset:      []rune(CharSetBase20),
				charAmount:   8,
				dashInterval: 4,
			},
			reader: rand.Reader,
		},
		{
			name: "crypto rand, digits",
			args: args{
				charset:      []rune(CharSetDigits),
				charAmount:   9,
				dashInterval: 3,
			},
			reader: rand.Reader,
		},
	}
	for _, tt := range tests {
		runWithRandReader(tt.reader, func() {
			b.Run(tt.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := NewUserCode(tt.args.charset, tt.args.charAmount, tt.args.dashInterval)
					require.NoError(b, err)
				}
			})

		})
	}
}
