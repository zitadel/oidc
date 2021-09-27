package strings

import "testing"

func TestContains(t *testing.T) {
	type args struct {
		list   []string
		needle string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"empty list false",
			args{[]string{}, "needle"},
			false,
		},
		{
			"list not containing false",
			args{[]string{"list"}, "needle"},
			false,
		},
		{
			"list not containing empty needle false",
			args{[]string{"list", "needle"}, ""},
			false,
		},
		{
			"list containing true",
			args{[]string{"list", "needle"}, "needle"},
			true,
		},
		{
			"list containing empty needle true",
			args{[]string{"list", "needle", ""}, ""},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.args.list, tt.args.needle); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}
