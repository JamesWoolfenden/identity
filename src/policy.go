package identity

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"net/url"
)

func GetAttachedGroupPolicies(group string) (iam.ListAttachedGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	input := &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(group),
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
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListAttachedGroupPoliciesOutput{}, nil
	}

	return *result, nil
}

func GetGroupPolicies(group string) (iam.ListGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)
	input := &iam.ListGroupPoliciesInput{
		GroupName: aws.String(group),
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

func GetUserPolicies(user string) (iam.ListUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	input := &iam.ListUserPoliciesInput{
		UserName: aws.String(user),
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

func GetAttachedUserPolicies(user string) (iam.ListAttachedUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	input := &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user),
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
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListAttachedUserPoliciesOutput{}, err
	}

	return *result, nil
}

func GetPolicy(arn string) (*string, error) {
	var result *iam.GetPolicyOutput
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

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

func GetUserPolicy(policy, user string) (*string, error) {
	var result *iam.GetUserPolicyOutput
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	result, err := svc.GetUserPolicy(&iam.GetUserPolicyInput{
		PolicyName: &policy,
		UserName:   &user,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicy(policy, role string) (*string, error) {
	var result *iam.GetRolePolicyOutput
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	result, err := svc.GetRolePolicy(&iam.GetRolePolicyInput{
		PolicyName: &policy,
		RoleName:   &role,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetGroupPolicy(policy, group string) (*string, error) {
	var result *iam.GetGroupPolicyOutput
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	result, err := svc.GetGroupPolicy(&iam.GetGroupPolicyInput{
		PolicyName: &policy,
		GroupName:  &group,
	})

	if err != nil {
		fmt.Println("Error", err)
		return nil, err
	}
	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicies(role string) (iam.ListRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	input := &iam.ListRolePoliciesInput{
		RoleName: aws.String(role),
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
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListRolePoliciesOutput{}, err
	}

	return *result, nil
}

func GetAttachedRolePolicies(user string) (iam.ListAttachedRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSession())
	svc := iam.New(mySession)

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(user),
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
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return iam.ListAttachedRolePoliciesOutput{}, err
	}

	return *result, nil
}

//  aws iam list-role-policies --role-name assume_role --profile default
// aws iam list-attached-role-policies --role-name assume_role --profile default
