package Identity

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/rs/zerolog/log"
)

func GetAttachedGroupPolicies(group IAM) (iam.ListAttachedGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(group))

	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListAttachedGroupPolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("Exception type: %s %s", iam.ErrCodeNoSuchEntityException, aerr)
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("Exception type: %s %s", iam.ErrCodeServiceFailureException, aerr)
			default:
				log.Error().Err(aerr)
			}

			return iam.ListAttachedGroupPoliciesOutput{}, aerr
		}
	}

	return *result, nil
}

func GetGroupPolicies(group IAM) (iam.ListGroupPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	credentials := stscreds.NewCredentials(mySession, FormatRole(group))

	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListGroupPolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Msg(aerr.Error())
			}
		}
		return iam.ListGroupPoliciesOutput{}, nil
	}

	return *result, nil
}

func GetUserPolicies(user IAM) (iam.ListUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	credentials := stscreds.NewCredentials(mySession, FormatRole(user))

	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListUserPolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Msgf("Please deploy the identity role %s", aerr)
			}
		}

		return iam.ListUserPoliciesOutput{}, err
	}

	return *result, nil
}

func GetAttachedUserPolicies(user IAM) (iam.ListAttachedUserPoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	credentials := stscreds.NewCredentials(mySession, FormatRole(user))

	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListAttachedUserPolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Err(aerr)
			}

			return iam.ListAttachedUserPoliciesOutput{}, aerr
		}
		return iam.ListAttachedUserPoliciesOutput{}, err
	}

	return *result, nil
}

func GetPolicy(arn string, account IAM) (*string, error) {
	var result *iam.GetPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	credentials := stscreds.NewCredentials(mySession, FormatRole(account))

	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	result, err := svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: &arn,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	version, err := svc.GetPolicyVersion(&iam.GetPolicyVersionInput{VersionId: result.Policy.DefaultVersionId, PolicyArn: result.Policy.Arn})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get policy version: %w", err)
	}

	temp, _ := url.QueryUnescape(*version.PolicyVersion.Document)
	return &temp, nil
}

func GetUserPolicy(policy string, ident IAM) (*string, error) {
	var result *iam.GetUserPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	result, err := svc.GetUserPolicy(&iam.GetUserPolicyInput{
		PolicyName: &policy,
		UserName:   &ident.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get user policies: %w", err)
	}

	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicy(policy string, ident IAM) (*string, error) {
	var result *iam.GetRolePolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	result, err := svc.GetRolePolicy(&iam.GetRolePolicyInput{
		PolicyName: &policy,
		RoleName:   &ident.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get role policies: %w", err)
	}

	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetGroupPolicy(policy string, group IAM) (*string, error) {
	var result *iam.GetGroupPolicyOutput
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(group))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	result, err := svc.GetGroupPolicy(&iam.GetGroupPolicyInput{
		PolicyName: &policy,
		GroupName:  &group.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get group policies: %w", err)
	}

	temp, _ := url.QueryUnescape(*result.PolicyDocument)
	return &temp, nil
}

func GetRolePolicies(ident IAM) (iam.ListRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListRolePolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Err(aerr)
			}

			return iam.ListRolePoliciesOutput{}, aerr
		}

		return iam.ListRolePoliciesOutput{}, err
	}

	return *result, nil
}

func GetUserGroups(ident IAM) (iam.ListGroupsForUserOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))

	credentials := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListGroupsForUserInput{
		UserName: aws.String(ident.Name),
	}

	result, err := svc.ListGroupsForUser(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Err(aerr)
			}

			return iam.ListGroupsForUserOutput{}, aerr
		}

		return iam.ListGroupsForUserOutput{}, err
	}

	return *result, nil
}

func GetAttachedRolePolicies(ident IAM) (iam.ListAttachedRolePoliciesOutput, error) {
	mySession := session.Must(session.NewSessionWithOptions(session.Options{Profile: "basic"}))
	credentials := stscreds.NewCredentials(mySession, FormatRole(ident))
	svc := iam.New(mySession, &aws.Config{Credentials: credentials})

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListAttachedRolePolicies(input)
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
			case iam.ErrCodeServiceFailureException:
				log.Error().Msgf("iam exception %s %s", iam.ErrCodeServiceFailureException, aerr.Error())
			default:
				log.Error().Err(aerr)
			}

			return iam.ListAttachedRolePoliciesOutput{}, aerr
		}

		return iam.ListAttachedRolePoliciesOutput{}, err
	}

	return *result, nil
}
