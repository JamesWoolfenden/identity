package Identity

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type IAM struct {
	Name     string   `json:"Name"`
	Account  string   `json:"Account"`
	IamType  string   `json:"IamType"`
	Policies []Policy `json:"Policies"`
}

type Policy struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// Statement is the core of an IAM policy.
type Statement struct {
	Sid      string   `json:"Sid"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

func SetIamType(result *sts.GetCallerIdentityOutput) (IAM, error) {
	var myIdentity IAM

	if strings.Contains(*result.Arn, ":user/") {
		myIdentity.IamType = UserType
		myIdentity.Name = strings.Split(*result.Arn, ":user/")[1]
		return myIdentity, nil
	}

	if strings.Contains(*result.Arn, ":group/") {
		myIdentity.IamType = GroupType
		myIdentity.Name = strings.Split(*result.Arn, ":group/")[1]
		return myIdentity, nil
	}

	if strings.Contains(*result.Arn, ":role/") {
		myIdentity.IamType = RoleType
		myIdentity.Name = strings.Split(*result.Arn, ":role/")[1]
		return myIdentity, nil
	}

	return myIdentity, fmt.Errorf("unable to determine iam type for %s", *result.Arn)
}

func GetIam() (IAM, error) {
	mySession := session.Must(session.NewSession())

	svc := sts.New(mySession)
	input := &sts.GetCallerIdentityInput{}

	result, err := svc.GetCallerIdentity(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return IAM{}, nil
	}

	iamIdentity, err := SetIamType(result)

	if err != nil {
		return IAM{}, fmt.Errorf("failed to set Iam Type: %w", err)
	}

	iamIdentity.Account = *result.Account

	switch iamIdentity.IamType {
	case UserType:
		UserPolicies, err := GetUserPolicies(iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get user policies: %w", err)
		}

		for _, v := range UserPolicies.PolicyNames {
			policyDocument, err := GetUserPolicy(*v, iamIdentity)

			if err != nil {
				return IAM{}, fmt.Errorf("failed to get user policies from policy names : %w", err)
			}

			Parsed, err := Parse(*policyDocument)
			if err != nil {
				return IAM{}, fmt.Errorf("failed to parse policy document: %w", err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		MoreUserPolicies, err := GetAttachedUserPolicies(iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get attached user policies: %w", err)
		}

		for _, v := range MoreUserPolicies.AttachedPolicies {
			raw, err := GetPolicy(*v.PolicyArn, iamIdentity)

			if err != nil {
				return IAM{}, fmt.Errorf("failed in call to getPolicy: %w", err)
			}

			Parsed, err := Parse(*raw)
			if err != nil {
				return IAM{}, err
			}
			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		//what groups is this user in?
		groups, err := GetUserGroups(iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get user groups: %w", err)
		}

		for _, v := range groups.Groups {
			tempIdentity := IAM{
				Name:    *v.GroupName,
				IamType: GroupType,
				Account: iamIdentity.Account,
			}

			groupPolicies, err := GetPoliciesForGroup(tempIdentity)

			if err != nil {
				return IAM{}, fmt.Errorf("failed to get user policies from group: %w", err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, groupPolicies.Policies...)
		}

	case GroupType:
		iam, err2 := GetPoliciesForGroup(iamIdentity)
		if err2 != nil {
			return iam, err2
		}
	case RoleType:
		RolePolicies, err := GetRolePolicies(iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get role policies: %w", err)
		}

		for _, v := range RolePolicies.PolicyNames {
			policyDocument, err := GetRolePolicy(*v, iamIdentity)

			if err != nil {
				return IAM{}, fmt.Errorf("failed to get role policies: %w", err)
			}

			Parsed, err := Parse(*policyDocument)

			if err != nil {
				return IAM{}, err
			}

			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		MoreRolePolicies, err := GetAttachedRolePolicies(iamIdentity)
		if err != nil {
			return IAM{}, fmt.Errorf("failed to get attached role policies: %w", err)
		}

		for _, v := range MoreRolePolicies.AttachedPolicies {
			policy, err := GetPolicy(*v.PolicyArn, iamIdentity)

			if err != nil {
				return IAM{}, fmt.Errorf("failed to get policies: %w", err)
			}

			Parsed, err := Parse(*policy)

			if err != nil {
				return IAM{}, err
			}

			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}
	default:
		return IAM{}, fmt.Errorf("failed to determine iam")
	}
	return iamIdentity, nil
}

func GetPoliciesForGroup(iamIdentity IAM) (IAM, error) {
	GroupPolicies, err := GetAttachedGroupPolicies(iamIdentity)

	if err != nil {
		return IAM{}, err
	}

	for _, v := range GroupPolicies.AttachedPolicies {
		raw, err := GetPolicy(*v.PolicyArn, iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get policies: %w", err)
		}

		Parsed, err := Parse(*raw)

		if err != nil {
			return IAM{}, err
		}
		iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
	}

	MoreGroupPolicies, err := GetGroupPolicies(iamIdentity)

	if err != nil {
		return IAM{}, fmt.Errorf("failed to get group policies: %w", err)
	}

	for _, v := range MoreGroupPolicies.PolicyNames {
		raw, err := GetGroupPolicy(*v, iamIdentity)

		if err != nil {
			return IAM{}, fmt.Errorf("failed to get group policies: %w", err)
		}

		Parsed, err := Parse(*raw)

		if err != nil {
			return IAM{}, err
		}

		iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
	}
	return iamIdentity, nil
}
