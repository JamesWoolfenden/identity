//go:build integration

package Identity

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestGetAttachedGroupPolicies(t *testing.T) {
	type args struct {
		group IAM
	}

	policies := []types.AttachedPolicy{
		{PolicyName: aws.String("assume-test-policy-forgroup"),
			PolicyArn: aws.String("arn:aws:iam::680235478471:policy/assume-test-policy-forgroup")},
	}

	result := &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: policies, IsTruncated: false}

	tests := []struct {
		name    string
		args    args
		want    *iam.ListAttachedGroupPoliciesOutput
		wantErr bool
	}{
		{"group", args{IAM{"idgroup", "680235478471", "", nil}}, result, false}, // TODO: Add test cases.
		{"nogroup", args{IAM{"mygroup", "680235478471", "", nil}}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedGroupPolicies(context.Background(), tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedGroupPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.AttachedPolicies, tt.want.AttachedPolicies) {
					t.Errorf("GetAttachedGroupPolicies() got = %v, want %v", got.AttachedPolicies, tt.want.AttachedPolicies)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetAttachedGroupPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAttachedRolePolicies(t *testing.T) {
	type args struct {
		user IAM
	}

	policies := []types.AttachedPolicy{
		{PolicyName: aws.String("assume-test-policy"),
			PolicyArn: aws.String("arn:aws:iam::680235478471:policy/assume-test-policy")},
	}

	result := &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: policies, IsTruncated: false}

	tests := []struct {
		name    string
		args    args
		want    *iam.ListAttachedRolePoliciesOutput
		wantErr bool
	}{
		{name: "role", args: args{IAM{"assume_role", "680235478471", "", nil}}, want: result, wantErr: false},
		{name: "bogus", args: args{IAM{"notexist", "680235478471", "", nil}}, want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedRolePolicies(context.Background(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedRolePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.AttachedPolicies, tt.want.AttachedPolicies) {
					t.Errorf("GetAttachedRolePolicies() got = %v, want %v", got.AttachedPolicies, tt.want.AttachedPolicies)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetAttachedRolePolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAttachedUserPolicies(t *testing.T) {
	type args struct {
		user IAM
	}

	tests := []struct {
		name    string
		args    args
		want    *iam.ListAttachedUserPoliciesOutput
		wantErr bool
	}{
		{"pass", args{IAM{
			"identity", "680235478471", "", nil,
		}}, &iam.ListAttachedUserPoliciesOutput{
			AttachedPolicies: []types.AttachedPolicy{{
				PolicyName: aws.String("test-policy"),
				PolicyArn:  aws.String("arn:aws:iam::680235478471:policy/test-policy"),
			}},
			IsTruncated: false},
			false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedUserPolicies(context.Background(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedUserPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.AttachedPolicies, tt.want.AttachedPolicies) {
					t.Errorf("GetAttachedUserPolicies() got = %v, want %v", got.AttachedPolicies, tt.want.AttachedPolicies)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetAttachedUserPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGroupPolicies(t *testing.T) {
	type args struct {
		group IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *iam.ListGroupPoliciesOutput
		wantErr bool
	}{
		{"Pass", args{IAM{"idgroup", "680235478471", "", nil}}, &iam.ListGroupPoliciesOutput{
			PolicyNames: []string{"my_developer_policy"},
			IsTruncated: false},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetGroupPolicies(context.Background(), tt.args.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetGroupPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.PolicyNames, tt.want.PolicyNames) {
					t.Errorf("GetGroupPolicies() got = %v, want %v", got.PolicyNames, tt.want.PolicyNames)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetGroupPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGroupPolicy(t *testing.T) {
	type args struct {
		policy string
		group  IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		{"Pass",
			args{"my_developer_policy", IAM{"idgroup", "680235478471", "", nil}}, aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetGroupPolicy(context.Background(), tt.args.policy, tt.args.group)
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
		arn     string
		account IAM
	}

	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		{"Pass",
			args{"arn:aws:iam::680235478471:policy/assume-test-policy",
				IAM{"pass", "680235478471", "", nil}},
			aws.String("{\"Statement\":[{\"Action\":\"s3:*\",\"Effect\":\"Allow\",\"Resource\":\"*\"}],\"Version\":\"2012-10-17\"}"),
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPolicy(context.Background(), tt.args.arn, tt.args.account)
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
		role IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *iam.ListRolePoliciesOutput
		wantErr bool
	}{
		{"pass", args{IAM{"assume_role", "680235478471", "", nil}},
			&iam.ListRolePoliciesOutput{
				PolicyNames: []string{"test_policy"},
				IsTruncated: false},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRolePolicies(context.Background(), tt.args.role)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRolePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.PolicyNames, tt.want.PolicyNames) {
					t.Errorf("GetRolePolicies() got = %v, want %v", got.PolicyNames, tt.want.PolicyNames)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetRolePolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRolePolicy(t *testing.T) {
	type args struct {
		policy string
		role   IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		{"Pass",
			args{"test_policy",
				IAM{"assume_role", "680235478471", "", nil}},
			aws.String("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRolePolicy(context.Background(), tt.args.policy, tt.args.role)
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
		user IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *iam.ListUserPoliciesOutput
		wantErr bool
	}{
		{"Pass", args{IAM{"identity", "680235478471", "", nil}}, &iam.ListUserPoliciesOutput{
			PolicyNames: []string{"test"},
			IsTruncated: false},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserPolicies(context.Background(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.PolicyNames, tt.want.PolicyNames) {
					t.Errorf("GetUserPolicies() got = %v, want %v", got.PolicyNames, tt.want.PolicyNames)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetUserPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserPolicy(t *testing.T) {
	type args struct {
		policy string
		user   IAM
	}
	want := "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"ec2:Describe*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"

	tests := []struct {
		name    string
		args    args
		want    *string
		wantErr bool
	}{
		{name: "Pass", args: args{policy: "test", user: IAM{"identity", "680235478471", "", nil}}, want: &want, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserPolicy(context.Background(), tt.args.policy, tt.args.user)
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

func TestGetAttachedUserPolicies1(t *testing.T) {
	type args struct {
		user IAM
	}
	tests := []struct {
		name    string
		args    args
		want    *iam.ListAttachedUserPoliciesOutput
		wantErr bool
	}{
		{"pass", args{
			IAM{"identity", "680235478471", "", nil}},
			&iam.ListAttachedUserPoliciesOutput{
				IsTruncated: false,
				AttachedPolicies: []types.AttachedPolicy{{
					PolicyName: aws.String("test-policy"),
					PolicyArn:  aws.String("arn:aws:iam::680235478471:policy/test-policy")}},
			},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAttachedUserPolicies(context.Background(), tt.args.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAttachedUserPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				if !reflect.DeepEqual(got.AttachedPolicies, tt.want.AttachedPolicies) {
					t.Errorf("GetAttachedUserPolicies() got = %v, want %v", got.AttachedPolicies, tt.want.AttachedPolicies)
				}
			} else if (got == nil) != (tt.want == nil) {
				t.Errorf("GetAttachedUserPolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}
