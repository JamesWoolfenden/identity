package Identity

import "testing"

func TestFormatRole(t *testing.T) {
	type args struct {
		user IAM
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"basic",
			args{IAM{"identity", "680235478471", "", nil}},
			"arn:aws:iam::680235478471:role/identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatRole(tt.args.user); got != tt.want {
				t.Errorf("FormatRole() = %v, want %v", got, tt.want)
			}
		})
	}
}
