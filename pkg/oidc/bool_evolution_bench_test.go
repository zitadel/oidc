package oidc

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// BoolOriginal - The original (Nov 2021) implementation
type BoolOriginal bool

func (bs *BoolOriginal) UnmarshalJSON(data []byte) error {
	if string(data) == "true" || string(data) == `"true"` {
		*bs = true
	}
	return nil
}

// BoolInitialPR - Proposal in https://github.com/zitadel/oidc/pull/791
// (try bool, fallback to string)
type BoolFirstPR bool

func (bs *BoolFirstPR) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*bs = BoolFirstPR(b)
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch strings.ToLower(s) {
		case "true":
			*bs = true
			return nil
		case "false":
			*bs = false
			return nil
		}
	}

	return fmt.Errorf("cannot unmarshal %s into Bool", data)
}

// BoolOptimized - Alternative optimized implementation
// (avoid unnecessary unmarshal attempts)
type BoolOptimized bool

func (bs *BoolOptimized) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("cannot unmarshal empty data into Bool")
	}

	switch data[0] {
	case 't', 'f': // boolean: true or false
		var b bool
		if err := json.Unmarshal(data, &b); err != nil {
			return err
		}
		*bs = BoolOptimized(b)
		return nil

	case '"': // string: "true" or "false"
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		switch strings.ToLower(s) {
		case "true":
			*bs = true
			return nil
		case "false":
			*bs = false
			return nil
		default:
			return fmt.Errorf("cannot unmarshal %q into Bool", s)
		}

	case 'n': // null
		*bs = false
		return nil

	default:
		return fmt.Errorf("cannot unmarshal %s into Bool", data)
	}
}

// I wanted to benchmark the different implementations to see how they perform with various inputs.
// The benchmarks cover standard boolean values, string representations, and null values.
// The goal is to ensure that the final implementation is both correct and efficient.
//
// Below, you'll find a progression of benchmarks for each version of the Bool type,
// as well as a comparative benchmark simulating a mixed real-world workload.
var evolutionTests = []struct {
	name string
	data []byte
}{
	{"BoolTrue", []byte(`true`)},
	{"BoolFalse", []byte(`false`)},
	{"StringTrue_AWS", []byte(`"true"`)},
	{"StringFalse_AWS", []byte(`"false"`)},
	{"StringTRUE_Mixed", []byte(`"TRUE"`)},
	{"Null", []byte(`null`)},
}

func BenchmarkEvolution_1_Original(b *testing.B) {
	for _, tt := range evolutionTests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var v BoolOriginal
				_ = v.UnmarshalJSON(tt.data)
			}
		})
	}
}

func BenchmarkEvolution_2_FirstPR(b *testing.B) {
	for _, tt := range evolutionTests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var v BoolFirstPR
				_ = v.UnmarshalJSON(tt.data)
			}
		})
	}
}

func BenchmarkEvolution_3_Optimized(b *testing.B) {
	for _, tt := range evolutionTests {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var v BoolOptimized
				_ = v.UnmarshalJSON(tt.data)
			}
		})
	}
}

// Comparative benchmark for mixed real-world workload
func BenchmarkEvolution_MixedWorkload(b *testing.B) {
	// Realistic distribution: 60% standard booleans, 40% AWS Cognito strings
	workload := [][]byte{
		[]byte(`true`),
		[]byte(`false`),
		[]byte(`true`),
		[]byte(`"true"`),
		[]byte(`"false"`),
	}

	b.Run("1_Original", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var v BoolOriginal
			_ = v.UnmarshalJSON(workload[i%len(workload)])
		}
	})

	b.Run("2_FirstPR", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var v BoolFirstPR
			_ = v.UnmarshalJSON(workload[i%len(workload)])
		}
	})

	b.Run("3_Optimized", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var v BoolOptimized
			_ = v.UnmarshalJSON(workload[i%len(workload)])
		}
	})
}
