package identity

import (
	"github.com/aws/aws-sdk-go/service/sts"
	"reflect"
	"testing"
)

func TestGetIam(t *testing.T) {
	myPolicy := []Policy{
		{
			Version: "2012-10-17",
			Statements: []Statement{
				{
					Sid:      "",
					Effect:   "Allow",
					Action:   []string{"s3:*", "s3-object-lambda:*"},
					Resource: []string{"*"},
				},
			},
		},
	}

	tests := []struct {
		name  string
		want  IAM
		want1 bool
	}{
		{"user", IAM{IamType: "user", Name: "jameswoolfenden", Policies: myPolicy}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetIam()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIam() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetIam() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

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
