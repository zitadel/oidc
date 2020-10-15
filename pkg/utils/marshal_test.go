package utils

import (
	"bytes"
	"testing"
)

func TestConcatenateJSON(t *testing.T) {
	type args struct {
		first  []byte
		second []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"invalid first part, error",
			args{
				[]byte(`invalid`),
				[]byte(`{"some": "thing"}`),
			},
			nil,
			true,
		},
		{
			"invalid second part, error",
			args{
				[]byte(`{"some": "thing"}`),
				[]byte(`invalid`),
			},
			nil,
			true,
		},
		{
			"both valid, merged",
			args{
				[]byte(`{"some": "thing"}`),
				[]byte(`{"another": "thing"}`),
			},

			[]byte(`{"some": "thing","another": "thing"}`),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConcatenateJSON(tt.args.first, tt.args.second)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConcatenateJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ConcatenateJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}
