package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"identity/src"
	"log"
	"strings"
)

func main() {
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
		return
	}

	iamIdentity, err := SetIamType(result)
	if err != nil {
		log.Fatal(err)
	}

	//override temp
	//iamIdentity.IamType = "role"
	//iamIdentity.Name = "assume_role"

	//iamIdentity.IamType = "user"
	//iamIdentity.Name = "identity"

	iamIdentity.IamType = "group"
	iamIdentity.Name = "idgroup"

	switch iamIdentity.IamType {
	case "user":
		UserPolicies, err := identity.GetUserPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range UserPolicies.PolicyNames {
			policyDocument, err := identity.GetUserPolicy(*v, iamIdentity.Name)
			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*policyDocument))
		}

		MoreUserPolicies, err := identity.GetAttachedUserPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreUserPolicies.AttachedPolicies {
			raw, err := identity.GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*raw))
		}
	case "group":
		GroupPolicies, err := identity.GetAttachedGroupPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range GroupPolicies.AttachedPolicies {
			raw, err := identity.GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*raw))
		}

		MoreGroupPolicies, err := identity.GetGroupPolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreGroupPolicies.PolicyNames {
			raw, err := identity.GetGroupPolicy(*v, iamIdentity.Name)

			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*raw))
		}
	case "role":
		RolePolicies, err := identity.GetRolePolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range RolePolicies.PolicyNames {
			policyDocument, err := identity.GetRolePolicy(*v, iamIdentity.Name)
			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*policyDocument))
		}

		MoreRolePolicies, err := identity.GetAttachedRolePolicies(iamIdentity.Name)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range MoreRolePolicies.AttachedPolicies {
			policy, err := identity.GetPolicy(*v.PolicyArn)

			if err != nil {
				log.Fatal(err)
			}

			iamIdentity.Policies = append(iamIdentity.Policies, identity.Parse(*policy))
		}
	default:
		log.Printf("failed to determine iam")
	}

	log.Print(iamIdentity)
}

func SetIamType(result *sts.GetCallerIdentityOutput) (identity.IAM, error) {
	var myIdentity identity.IAM

	if strings.Contains(*result.Arn, ":user/") {
		myIdentity.IamType = "user"
		myIdentity.Name = strings.Split(*result.Arn, ":user/")[1]
	}

	if strings.Contains(*result.Arn, ":group/") {
		myIdentity.IamType = "group"
		myIdentity.Name = strings.Split(*result.Arn, ":group/")[1]
	}

	if strings.Contains(*result.Arn, ":role/") {
		myIdentity.IamType = "role"
		myIdentity.Name = strings.Split(*result.Arn, ":role/")[1]
	}

	return myIdentity, nil
}
