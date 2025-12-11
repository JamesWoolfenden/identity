package Identity

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
		{"fail", args{"guff"}, NewPolicy()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := Parse(tt.args.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
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

func TestEmptyParseError_Error(t *testing.T) {
	tests := []struct {
		name string
		m    *EmptyParseError
		want string
	}{
		{
			name: "empty_error_message",
			m:    &EmptyParseError{},
			want: "cannot parse such empty",
		},
		{
			name: "nil_error",
			m:    nil,
			want: "cannot parse such empty",
		},
		{
			name: "new_empty_error",
			m:    new(EmptyParseError),
			want: "cannot parse such empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.Error(); got != tt.want {
				t.Errorf("EmptyParseError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEdgeCases(t *testing.T) {
	type args struct {
		raw string
	}
	tests := []struct {
		name    string
		args    args
		want    Policy
		wantErr bool
	}{
		{
			name:    "empty_string",
			args:    args{raw: ""},
			want:    NewPolicy(),
			wantErr: true,
		},
		{
			name:    "invalid_json",
			args:    args{raw: "{not a json}"},
			want:    NewPolicy(),
			wantErr: true,
		},
		{
			name:    "missing_version",
			args:    args{raw: `{"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"]}]}`},
			want:    NewPolicy(),
			wantErr: true,
		},
		{
			name: "single_statement_not_array",
			args: args{raw: `{
				"Version": "2012-10-17",
				"Statement": {"Effect": "Deny", "Action": "s3:*", "Resource": "*"}
			}`},
			want: Policy{
				Version: "2012-10-17",
				Statements: []Statement{{
					Effect:   "Deny",
					Action:   []string{"s3:*"},
					Resource: []string{"*"},
				}},
			},
			wantErr: false,
		},
		{
			name: "multiple_statements",
			args: args{raw: `{
				"Version": "2012-10-17",
				"Statement": [
					{"Effect": "Allow", "Action": ["s3:Get*"], "Resource": ["arn:aws:s3:::bucket/*"]},
					{"Effect": "Deny", "Action": ["s3:Delete*"], "Resource": ["*"]}
				]
			}`},
			want: Policy{
				Version: "2012-10-17",
				Statements: []Statement{
					{
						Effect:   "Allow",
						Action:   []string{"s3:Get*"},
						Resource: []string{"arn:aws:s3:::bucket/*"},
					},
					{
						Effect:   "Deny",
						Action:   []string{"s3:Delete*"},
						Resource: []string{"*"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "with_sid",
			args: args{raw: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "1",
					"Effect": "Allow",
					"Action": ["s3:*"],
					"Resource": ["*"]
				}]
			}`},
			want: Policy{
				Version: "2012-10-17",
				Statements: []Statement{{
					Sid:      "1",
					Effect:   "Allow",
					Action:   []string{"s3:*"},
					Resource: []string{"*"},
				}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
