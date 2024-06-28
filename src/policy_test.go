package identity

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"reflect"
	"testing"
)

func TestGetAttachedGroupPolicies(t *testing.T) {
	type args struct {
		group string
	}

	policies := []*iam.AttachedPolicy{
		{PolicyName: aws.String("assume-test-policy-forgroup"),
			PolicyArn: aws.String("arn:aws:iam::680235478471:policy/assume-test-policy-forgroup")},
	}

	result := iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: policies, IsTruncated: aws.Bool(false)}

	tests := []struct {
		name    string
		args    args
		want    iam.ListAttachedGroupPoliciesOutput
		wantErr bool
	}{
		{"group", args{"idgroup"}, result, false}, // TODO: Add test cases.
		{"nogroup", args{"mygroup"}, iam.ListAttachedGroupPoliciesOutput{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedGroupPolicies(tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedGroupPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAttachedGroupPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAttachedRolePolicies(t *testing.T) {
	type args struct {
		user string
	}

	policies := []*iam.AttachedPolicy{
		{PolicyName: aws.String("assume-test-policy"),
			PolicyArn: aws.String("arn:aws:iam::680235478471:policy/assume-test-policy")},
	}

	result := iam.ListAttachedRolePoliciesOutput{AttachedPolicies: policies, IsTruncated: aws.Bool(false)}

	tests := []struct {
		name    string
		args    args
		want    iam.ListAttachedRolePoliciesOutput
		wantErr bool
	}{
		{name: "role", args: args{"assume_role"}, want: result, wantErr: false},
		{name: "bogus", args: args{"notexist"}, want: iam.ListAttachedRolePoliciesOutput{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedRolePolicies(tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedRolePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAttachedRolePolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAttachedUserPolicies(t *testing.T) {
	type args struct {
		user string
	}
	tests := []struct {
		name    string
		args    args
		want    iam.ListAttachedUserPoliciesOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedUserPolicies(tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedUserPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAttachedUserPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGroupPolicies(t *testing.T) {
	type args struct {
		group string
	}
	tests := []struct {
		name    string
		args    args
		want    iam.ListGroupPoliciesOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetGroupPolicies(tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetGroupPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetGroupPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGroupPolicy(t *testing.T) {
	type args struct {
		policy string
		group  string
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetGroupPolicy(tt.args.policy, tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetGroupPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetGroupPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPolicy(t *testing.T) {
	type args struct {
		arn string
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPolicy(tt.args.arn)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRolePolicies(t *testing.T) {
	type args struct {
		role string
	}
	tests := []struct {
		name    string
		args    args
		want    iam.ListRolePoliciesOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRolePolicies(tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRolePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRolePolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRolePolicy(t *testing.T) {
	type args struct {
		policy string
		role   string
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRolePolicy(tt.args.policy, tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRolePolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRolePolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserPolicies(t *testing.T) {
	type args struct {
		user string
	}
	tests := []struct {
		name    string
		args    args
		want    iam.ListUserPoliciesOutput
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserPolicies(tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUserPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserPolicy(t *testing.T) {
	type args struct {
		policy string
		user   string
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserPolicy(tt.args.policy, tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUserPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}