//go:build integration

package Identity

import (
	"context"
	"reflect"
	"testing"
)

func TestGetIam(t *testing.T) {
	myPolicy := []Policy{
		{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Sid:      "VisualEditor0",
					Effect:   "Allow",
					Action:   []string{"ec2:DescribeVpnConnections", "rds:DescribeGlobalClusters", "ecr-public:DescribeImages"},
					Resource: []string{"*"},
				},
			},
		},
	}

	tests := []struct {
		name    string
		want    IAM
		wantErr bool
	}{
		//not a very good test as its current retreiving what the used iAM context is
		{"user", IAM{IamType: "user", Name: "basic", Account: "680235478471", Policies: myPolicy}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetIam(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIam() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPoliciesForGroup(t *testing.T) {
	tests := []struct {
		name    string
		input   IAM
		want    IAM
		wantErr bool
	}{
		{
			name: "empty_group",
			input: IAM{
				Name:     "emptypolicygroup",
				IamType:  "group",
				Account:  "680235478471",
				Policies: nil,
			},
			want: IAM{
				Name:     "emptypolicygroup",
				IamType:  "group",
				Account:  "680235478471",
				Policies: nil,
			},
			wantErr: false,
		},
		{
			name: "group_with_multiple_policies",
			input: IAM{
				Name:     "multipolicygroup",
				IamType:  "group",
				Account:  "680235478471",
				Policies: nil,
			},
			want: IAM{
				Name:    "multipolicygroup",
				IamType: "group",
				Account: "680235478471",
				Policies: []Policy{
					{
						Version: "2012-10-17",
						Statements: []Statement{
							{
								Effect:   "Allow",
								Action:   []string{"s3:ListBucket"},
								Resource: []string{"*"},
							},
						},
					},
					{
						Version: "2012-10-17",
						Statements: []Statement{
							{
								Effect:   "Deny",
								Action:   []string{"iam:*"},
								Resource: []string{"*"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid_group_type",
			input: IAM{
				Name:     "invalidgroup",
				IamType:  "user",
				Account:  "680235478471",
				Policies: nil,
			},
			want:    IAM{},
			wantErr: true,
		},
		{
			name: "nonexistent_group",
			input: IAM{
				Name:     "nonexistentgroup",
				IamType:  "group",
				Account:  "680235478471",
				Policies: nil,
			},
			want:    IAM{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPoliciesForGroup(context.Background(), tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPoliciesForGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPoliciesForGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}
