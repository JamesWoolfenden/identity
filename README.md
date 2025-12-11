# Identity

A Go tool for retrieving and analyzing AWS IAM policies for users, groups, and roles.

## Overview

Identity is a command-line tool that retrieves the IAM policies associated with your current AWS identity (user, group, or role). It fetches both inline and attached policies, including policies inherited through group memberships.

## Features

- Retrieves IAM policies for users, groups, and roles
- Supports both inline and attached policies
- Fetches group policies for users automatically
- Parses and structures IAM policy documents
- Configurable AWS profile and IAM role
- Built-in error handling and logging

## Installation

```bash
go install github.com/jameswoolfenden/identity@latest
```

Or build from source:

```bash
git clone https://github.com/jameswoolfenden/identity.git
cd identity
go build
```

## Usage

### Basic Usage

Run the tool to get your current IAM identity and associated policies:

```bash
./identity
```

### Configuration

The tool supports configuration through environment variables:

#### AWS Profile

By default, the tool uses the `basic` AWS profile. You can override this by setting:

```bash
export AWS_PROFILE=your-profile-name
./identity
```

#### IAM Role Name

The tool assumes an IAM role named `identity` to retrieve policy information. You can customize this:

```bash
export IAM_ROLE_NAME=your-role-name
./identity
```

### AWS Setup Requirements

1. **AWS Credentials**: Ensure you have AWS credentials configured in `~/.aws/credentials` or through environment variables.

2. **IAM Role**: The tool requires an IAM role with the following permissions:
   - `sts:GetCallerIdentity`
   - `iam:ListUserPolicies`
   - `iam:ListAttachedUserPolicies`
   - `iam:GetUserPolicy`
   - `iam:GetPolicy`
   - `iam:GetPolicyVersion`
   - `iam:ListGroupsForUser`
   - `iam:ListGroupPolicies`
   - `iam:ListAttachedGroupPolicies`
   - `iam:GetGroupPolicy`
   - `iam:ListRolePolicies`
   - `iam:ListAttachedRolePolicies`
   - `iam:GetRolePolicy`

3. **Trust Relationship**: The IAM role must have a trust relationship allowing your user/role to assume it.

### Example IAM Role

You can create the required IAM role using the Terraform/OpenTofu templates in the `terraform/` directory:

```bash
cd terraform/role
tofu init
tofu apply
```

## Output

The tool outputs JSON containing:

- **Name**: The IAM entity name
- **Account**: AWS account ID
- **IamType**: Type of identity (user, group, or role)
- **Policies**: Array of policy documents with statements

Example output:

```json
{
  "Name": "my-user",
  "Account": "123456789012",
  "IamType": "user",
  "Policies": [
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "AllowS3Access",
          "Effect": "Allow",
          "Action": ["s3:GetObject", "s3:PutObject"],
          "Resource": ["arn:aws:s3:::my-bucket/*"]
        }
      ]
    }
  ]
}
```

## Development

### Running Tests

```bash
go test ./... -v
```

### Code Quality

The project uses several code quality tools configured via pre-commit hooks:

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Building

```bash
go build -o identity
```

## Project Structure

```
.
├── main.go              # Entry point
├── src/
│   ├── iam.go          # Core IAM identity and policy retrieval
│   ├── policy.go       # AWS IAM API interactions
│   ├── parse.go        # Policy document parsing
│   ├── format.go       # ARN formatting utilities
│   └── *_test.go       # Test files
├── terraform/          # Infrastructure as Code templates
│   ├── role/          # IAM role definitions
│   ├── group/         # IAM group definitions
│   └── user/          # IAM user definitions
└── README.md          # This file
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code is formatted: `gofmt -w .`
3. Pre-commit hooks pass
4. New features include tests

## License

See LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
