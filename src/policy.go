package identity

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"net/url"
)

func GetAttachedGroupPolicies(group IAM) (iam.ListAttachedGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(group))

	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListAttachedGroupPolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}

			return iam.ListAttachedGroupPoliciesOutput{}, aerr
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	}

	return *result, nil
}

func GetGroupPolicies(group IAM) (iam.ListGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	creds := stscreds.NewCredentials(mySession, FormatRole(group))

	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListGroupPolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListGroupPoliciesOutput{}, nil
	}

	return *result, nil
}

func GetUserPolicies(user IAM) (iam.ListUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	creds := stscreds.NewCredentials(mySession, FormatRole(user))

	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListUserPolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println("Please deploy the identity role")
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.

			fmt.Println(err.Error())
		}
		return iam.ListUserPoliciesOutput{}, err
	}

	return *result, nil
}

func GetAttachedUserPolicies(user IAM) (iam.ListAttachedUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	creds := stscreds.NewCredentials(mySession, FormatRole(user))

	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListAttachedUserPolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
			return iam.ListAttachedUserPoliciesOutput{}, aerr
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListAttachedUserPoliciesOutput{}, err
	}

	return *result, nil
}

func GetPolicy(arn string, account IAM) (*string, error) {
	var result *iam.GetPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	creds := stscreds.NewCredentials(mySession, FormatRole(account))

	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	result, err := svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: &arn,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}

	version, err := svc.GetPolicyVersion(&iam.GetPolicyVersionInput{VersionId: result.Policy.DefaultVersionId, PolicyArn: result.Policy.Arn})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}

	temp, _ := url.QueryUnescape(*version.PolicyVersion.Document)
	return &temp, nil
}

func GetUserPolicy(policy string, ident IAM) (*string, error) {
	var result *iam.GetUserPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	result, err := svc.GetUserPolicy(&iam.GetUserPolicyInput{
		PolicyName: &policy,
		UserName:   &ident.Name,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicy(policy string, ident IAM) (*string, error) {
	var result *iam.GetRolePolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	result, err := svc.GetRolePolicy(&iam.GetRolePolicyInput{
		PolicyName: &policy,
		RoleName:   &ident.Name,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetGroupPolicy(policy string, group IAM) (*string, error) {
	var result *iam.GetGroupPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(group))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	result, err := svc.GetGroupPolicy(&iam.GetGroupPolicyInput{
		PolicyName: &policy,
		GroupName:  &group.Name,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicies(ident IAM) (iam.ListRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListRolePolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}

			return iam.ListRolePoliciesOutput{}, aerr
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListRolePoliciesOutput{}, err
	}

	return *result, nil
}

func GetUserGroups(ident IAM) (iam.ListGroupsForUserOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	creds := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListGroupsForUserInput{
		UserName: aws.String(ident.Name),
	}

	result, err := svc.ListGroupsForUser(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}

			return iam.ListGroupsForUserOutput{}, aerr
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListGroupsForUserOutput{}, err
	}

	return *result, nil
}

func GetAttachedRolePolicies(ident IAM) (iam.ListAttachedRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	creds := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: creds})

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListAttachedRolePolicies(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				fmt.Println(iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				fmt.Println(iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}

			return iam.ListAttachedRolePoliciesOutput{}, aerr
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListAttachedRolePoliciesOutput{}, err
	}

	return *result, nil
}
