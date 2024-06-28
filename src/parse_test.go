package identity

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name string
		args args
		want Policy
	}{
		{"pass", args{"{\n    \"Version\": \"2012-10-17\",\n    \"Statement\": [\n        {\n            \"Effect\": \"Allow\",\n            \"Action\": [\"s3:*\",\"s3-object-lambda:*\"],\n            \"Resource\": [\"*\"]\n        }\n    ]\n}"},
			Policy{Version: "2012-10-17", Statements: []Statement{{Sid: "", Effect: "Allow", Action: []string{"s3:*", "s3-object-lambda:*"}, Resource: []string{"*"}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(tt.args.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isArray(t *testing.T) {
	type args struct {
		arr interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"array", args{[5]int{1, 2, 3, 4, 5}}, true},
		{"string", args{"a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isArray(tt.args.arr); got != tt.want {
				t.Errorf("isArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSlice(t *testing.T) {
	type args struct {
		arr interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"array", args{[]string{"1", "2", "3", "4", "5"}}, true},
		{"string", args{"a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSlice(tt.args.arr); got != tt.want {
				t.Errorf("isSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}
