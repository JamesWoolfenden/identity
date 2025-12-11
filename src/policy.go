package Identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/rs/zerolog/log"
)

const defaultProfile = "basic"

// GetAWSProfile returns the AWS profile to use, from env var or default
func GetAWSProfile() string {
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		return profile
	}
	return defaultProfile
}

// getConfigWithAssumedRole returns an AWS config with assumed role credentials
func getConfigWithAssumedRole(ctx context.Context, account IAM) (aws.Config, error) {
	// Load base config with profile
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(GetAWSProfile()))
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load config: %w", err)
	}

	// Create STS client for assuming role
	stsClient := sts.NewFromConfig(cfg)

	// Create credentials provider that assumes the role
	roleARN := FormatRole(account)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN)

	// Create new config with assumed role credentials
	cfg.Credentials = aws.NewCredentialsCache(provider)

	return cfg, nil
}

func GetAttachedGroupPolicies(ctx context.Context, group IAM) (*iam.ListAttachedGroupPoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListAttachedGroupPolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("Exception type: NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("Exception type: ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Err(err)
		}
		return nil, err
	}

	return result, nil
}

func GetGroupPolicies(ctx context.Context, group IAM) (*iam.ListGroupPoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListGroupPoliciesInput{
		GroupName: aws.String(group.Name),
	}

	result, err := svc.ListGroupPolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Msg(err.Error())
		}
		return nil, err
	}

	return result, nil
}

func GetUserPolicies(ctx context.Context, user IAM) (*iam.ListUserPoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListUserPolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Msgf("Please deploy the identity role %s", err)
		}
		return nil, err
	}

	return result, nil
}

func GetAttachedUserPolicies(ctx context.Context, user IAM) (*iam.ListAttachedUserPoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user.Name),
	}

	result, err := svc.ListAttachedUserPolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Err(err)
		}
		return nil, err
	}

	return result, nil
}

func GetPolicy(ctx context.Context, arn string, account IAM) (*string, error) {
	cfg, err := getConfigWithAssumedRole(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	result, err := svc.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: &arn,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	version, err := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		VersionId: result.Policy.DefaultVersionId,
		PolicyArn: result.Policy.Arn,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get policy version: %w", err)
	}

	temp, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape policy document: %w", err)
	}
	return &temp, nil
}

func GetUserPolicy(ctx context.Context, policy string, ident IAM) (*string, error) {
	cfg, err := getConfigWithAssumedRole(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	result, err := svc.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
		PolicyName: &policy,
		UserName:   &ident.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get user policies: %w", err)
	}

	temp, err := url.QueryUnescape(*result.PolicyDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape policy document: %w", err)
	}
	return &temp, nil
}

func GetRolePolicy(ctx context.Context, policy string, ident IAM) (*string, error) {
	cfg, err := getConfigWithAssumedRole(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	result, err := svc.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
		PolicyName: &policy,
		RoleName:   &ident.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get role policies: %w", err)
	}

	temp, err := url.QueryUnescape(*result.PolicyDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape policy document: %w", err)
	}
	return &temp, nil
}

func GetGroupPolicy(ctx context.Context, policy string, group IAM) (*string, error) {
	cfg, err := getConfigWithAssumedRole(ctx, group)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	result, err := svc.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
		PolicyName: &policy,
		GroupName:  &group.Name,
	})

	if err != nil {
		log.Error().Err(err)
		return nil, fmt.Errorf("failed to get group policies: %w", err)
	}

	temp, err := url.QueryUnescape(*result.PolicyDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape policy document: %w", err)
	}
	return &temp, nil
}

func GetRolePolicies(ctx context.Context, ident IAM) (*iam.ListRolePoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListRolePolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Err(err)
		}
		return nil, err
	}

	return result, nil
}

func GetUserGroups(ctx context.Context, ident IAM) (*iam.ListGroupsForUserOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListGroupsForUserInput{
		UserName: aws.String(ident.Name),
	}

	result, err := svc.ListGroupsForUser(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Err(err)
		}
		return nil, err
	}

	return result, nil
}

func GetAttachedRolePolicies(ctx context.Context, ident IAM) (*iam.ListAttachedRolePoliciesOutput, error) {
	cfg, err := getConfigWithAssumedRole(ctx, ident)
	if err != nil {
		return nil, fmt.Errorf("failed to get config with assumed role: %w", err)
	}

	svc := iam.NewFromConfig(cfg)

	input := &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(ident.Name),
	}

	result, err := svc.ListAttachedRolePolicies(ctx, input)
	if err != nil {
		var nse *types.NoSuchEntityException
		var sfe *types.ServiceFailureException
		if errors.As(err, &nse) {
			log.Error().Msgf("iam exception NoSuchEntity %s", *nse.Message)
		} else if errors.As(err, &sfe) {
			log.Error().Msgf("iam exception ServiceFailure %s", *sfe.Message)
		} else {
			log.Error().Err(err)
		}
		return nil, err
	}

	return result, nil
}
