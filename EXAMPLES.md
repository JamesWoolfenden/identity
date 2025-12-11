# Identity Usage Examples

This document provides practical examples for using the Identity tool.

## Command Line Usage

### Example 1: Basic Usage with Default Profile

```bash
# Uses the 'basic' AWS profile by default
./identity
```

Output:
```json
{"Name":"john.doe","Account":"123456789012","IamType":"user","Policies":[...]}
```

### Example 2: Using a Custom AWS Profile

```bash
# Use a specific AWS profile
export AWS_PROFILE=production
./identity
```

### Example 3: Using a Custom IAM Role

```bash
# Use a different IAM role name
export IAM_ROLE_NAME=my-custom-identity-role
./identity
```

### Example 4: Combining Custom Profile and Role

```bash
# Set both profile and role name
export AWS_PROFILE=staging
export IAM_ROLE_NAME=identity-reader
./identity
```

## Programmatic Usage

### Example 1: Get Current Identity

```go
package main

import (
    "fmt"
    "log"

    Identity "github.com/jameswoolfenden/identity/src"
)

func main() {
    iamIdentity, err := Identity.GetIam()
    if err != nil {
        log.Fatalf("Failed to get IAM identity: %v", err)
    }

    fmt.Printf("Identity Type: %s\n", iamIdentity.IamType)
    fmt.Printf("Name: %s\n", iamIdentity.Name)
    fmt.Printf("Account: %s\n", iamIdentity.Account)
    fmt.Printf("Number of Policies: %d\n", len(iamIdentity.Policies))
}
```

### Example 2: Parse a Policy Document

```go
package main

import (
    "fmt"
    "log"

    Identity "github.com/jameswoolfenden/identity/src"
)

func main() {
    policyJSON := `{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            }
        ]
    }`

    policy, err := Identity.Parse(policyJSON)
    if err != nil {
        log.Fatalf("Failed to parse policy: %v", err)
    }

    fmt.Printf("Policy Version: %s\n", policy.Version)
    for _, stmt := range policy.Statements {
        fmt.Printf("Effect: %s\n", stmt.Effect)
        fmt.Printf("Actions: %v\n", stmt.Action)
        fmt.Printf("Resources: %v\n", stmt.Resource)
    }
}
```

### Example 3: Get Policies for a Specific Group

```go
package main

import (
    "fmt"
    "log"

    Identity "github.com/jameswoolfenden/identity/src"
)

func main() {
    group := Identity.IAM{
        Name:    "developers",
        IamType: Identity.GroupType,
        Account: "123456789012",
    }

    groupWithPolicies, err := Identity.GetPoliciesForGroup(group)
    if err != nil {
        log.Fatalf("Failed to get group policies: %v", err)
    }

    fmt.Printf("Group: %s\n", groupWithPolicies.Name)
    fmt.Printf("Policies: %d\n", len(groupWithPolicies.Policies))

    for i, policy := range groupWithPolicies.Policies {
        fmt.Printf("\nPolicy %d:\n", i+1)
        for _, stmt := range policy.Statements {
            fmt.Printf("  Actions: %v\n", stmt.Action)
        }
    }
}
```

### Example 4: List All Actions from User's Policies

```go
package main

import (
    "fmt"
    "log"

    Identity "github.com/jameswoolfenden/identity/src"
)

func main() {
    iamIdentity, err := Identity.GetIam()
    if err != nil {
        log.Fatalf("Failed to get IAM identity: %v", err)
    }

    fmt.Printf("All IAM actions for %s:\n", iamIdentity.Name)

    actionMap := make(map[string]bool)
    for _, policy := range iamIdentity.Policies {
        for _, stmt := range policy.Statements {
            if stmt.Effect == "Allow" {
                for _, action := range stmt.Action {
                    actionMap[action] = true
                }
            }
        }
    }

    for action := range actionMap {
        fmt.Printf("  - %s\n", action)
    }
}
```

### Example 5: Check if User Has Specific Permission

```go
package main

import (
    "fmt"
    "log"
    "strings"

    Identity "github.com/jameswoolfenden/identity/src"
)

func hasPermission(iamIdentity Identity.IAM, targetAction string) bool {
    for _, policy := range iamIdentity.Policies {
        for _, stmt := range policy.Statements {
            if stmt.Effect != "Allow" {
                continue
            }

            for _, action := range stmt.Action {
                if action == targetAction || action == "*" {
                    return true
                }

                // Handle wildcard patterns like "s3:*"
                if strings.HasSuffix(action, ":*") {
                    prefix := strings.TrimSuffix(action, ":*")
                    if strings.HasPrefix(targetAction, prefix+":") {
                        return true
                    }
                }
            }
        }
    }
    return false
}

func main() {
    iamIdentity, err := Identity.GetIam()
    if err != nil {
        log.Fatalf("Failed to get IAM identity: %v", err)
    }

    permissions := []string{
        "s3:GetObject",
        "ec2:DescribeInstances",
        "iam:CreateUser",
    }

    fmt.Printf("Permission check for %s:\n", iamIdentity.Name)
    for _, perm := range permissions {
        hasIt := hasPermission(iamIdentity, perm)
        fmt.Printf("  %s: %v\n", perm, hasIt)
    }
}
```

## Advanced Examples

### Setting Up the Identity Role with Terraform/OpenTofu

```bash
# Navigate to the role directory
cd terraform/role

# Initialize Terraform/OpenTofu
tofu init

# Review the plan
tofu plan

# Apply the configuration
tofu apply

# The role ARN will be output
# Update your AWS config to allow assuming this role
```

### Using with Multiple AWS Accounts

```bash
# Create a script to check identity across multiple accounts
#!/bin/bash

PROFILES=("dev" "staging" "prod")

for profile in "${PROFILES[@]}"; do
    echo "=== Checking identity for profile: $profile ==="
    export AWS_PROFILE=$profile
    ./identity
    echo ""
done
```

### Integration with CI/CD

```yaml
# GitHub Actions example
name: Check IAM Permissions
on: [push]

jobs:
  check-permissions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.22'

      - name: Build identity tool
        run: go build

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Check current identity
        run: ./identity
```

## Troubleshooting

### Issue: "The role with name identity cannot be found"

**Solution**: Create the identity role or set a custom role name:
```bash
export IAM_ROLE_NAME=your-existing-role
```

### Issue: "AccessDenied" errors

**Solution**: Ensure your user/role has permission to assume the identity role and that the role has the necessary IAM read permissions.

### Issue: Empty policies returned

**Solution**: Check that:
1. The identity actually has policies attached
2. The assumed role has permission to read those policies
3. You're using the correct AWS profile

## Performance Tips

1. **Cache Results**: The tool makes multiple API calls. Consider caching the results if checking frequently.
2. **Minimal Role**: Create a dedicated read-only role with only the minimum required IAM permissions.
3. **Parallel Processing**: When checking multiple identities, use goroutines to parallelize the calls.

## Security Best Practices

1. **Least Privilege**: Only grant the identity role the minimum IAM read permissions needed.
2. **Audit Logging**: Enable CloudTrail to log all identity role assumptions.
3. **Session Duration**: Configure the role with a short session duration (e.g., 1 hour).
4. **MFA**: Require MFA to assume the identity role in production environments.
