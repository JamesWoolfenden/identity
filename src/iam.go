package identity

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"log"
	"strings"
)

type IAM struct {
	Name     string   `json:"Name"`
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
		myIdentity.IamType = "user"
		myIdentity.Name = strings.Split(*result.Arn, ":user/")[1]
		return myIdentity, nil
	}

	if strings.Contains(*result.Arn, ":group/") {
		myIdentity.IamType = "group"
		myIdentity.Name = strings.Split(*result.Arn, ":group/")[1]
		return myIdentity, nil
	}

	if strings.Contains(*result.Arn, ":role/") {
		myIdentity.IamType = "role"
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
		log.Fatal(err)
	}

	switch iamIdentity.IamType {
	case "user":
		UserPolicies, err := GetUserPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range UserPolicies.PolicyNames {
			policyDocument, err := GetUserPolicy(*v, iamIdentity.Name)
			if err != nil {
				log.Fatal(err)
			}

			Parsed, err := Parse(*policyDocument)
			if err != nil {
				return IAM{}, err
			}

			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		MoreUserPolicies, err := GetAttachedUserPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreUserPolicies.AttachedPolicies {
			raw, err := GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
			}

			Parsed, err := Parse(*raw)
			if err != nil {
				return IAM{}, err
			}
			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}
	case "group":
		GroupPolicies, err := GetAttachedGroupPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range GroupPolicies.AttachedPolicies {
			raw, err := GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
			}

			Parsed, err := Parse(*raw)
			if err != nil {
				return IAM{}, err
			}
			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		MoreGroupPolicies, err := GetGroupPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreGroupPolicies.PolicyNames {
			raw, err := GetGroupPolicy(*v, iamIdentity.Name)

			if err != nil {
				log.Fatal(err)
			}

			Parsed, err := Parse(*raw)
			if err != nil {
				return IAM{}, err
			}
			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}
	case "role":
		RolePolicies, err := GetRolePolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range RolePolicies.PolicyNames {
			policyDocument, err := GetRolePolicy(*v, iamIdentity.Name)
			if err != nil {
				log.Fatal(err)
			}

			Parsed, err := Parse(*policyDocument)
			if err != nil {
				return IAM{}, err
			}
			iamIdentity.Policies = append(iamIdentity.Policies, Parsed)
		}

		MoreRolePolicies, err := GetAttachedRolePolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreRolePolicies.AttachedPolicies {
			policy, err := GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
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
