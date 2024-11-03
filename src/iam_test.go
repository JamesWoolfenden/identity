package Identity

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/service/sts"
)

func TestSetIamType(t *testing.T) {
	type args struct {
		result *sts.GetCallerIdentityOutput
	}

	account := "680235478471"
	grouparn := "arn:aws:iam::680235478471:group/idgroup"
	userarn := "arn:aws:iam::680235478471:user/idgroup"
	rolearn := "arn:aws:iam::680235478471:role/idgroup"
	bogusarn := "arn:aws:iam::680235478471:bogus/idgroup"
	userId := ""

	bogus := sts.GetCallerIdentityOutput{
		Account: &account,
		Arn:     &bogusarn,
		UserId:  &userId,
	}

	role := sts.GetCallerIdentityOutput{
		Account: &account,
		Arn:     &rolearn,
		UserId:  &userId,
	}

	user := sts.GetCallerIdentityOutput{
		Account: &account,
		Arn:     &userarn,
		UserId:  &userId,
	}

	group := sts.GetCallerIdentityOutput{
		Account: &account,
		Arn:     &grouparn,
		UserId:  &userId,
	}

	tests := []struct {
		name    string
		args    args
		want    IAM
		wantErr bool
	}{
		{"group", args{&group}, IAM{Name: "idgroup", IamType: "group", Policies: nil}, false},
		{"user", args{&user}, IAM{Name: "idgroup", IamType: "user", Policies: nil}, false},
		{"role", args{&role}, IAM{Name: "idgroup", IamType: "role", Policies: nil}, false},
		{"bogus", args{&bogus}, IAM{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetIamType(tt.args.result)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetIamType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetIamType() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetIam(t *testing.T) {
	myPolicy := []Policy{
		{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Sid:      "VisualEditor0",
					Effect:   "Allow",
					Action:   []string{"ssm:DescribePatchBaselines"},
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
			got, err := GetIam()
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
			got, err := GetPoliciesForGroup(tt.input)
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
