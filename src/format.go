package Identity

import (
	"fmt"
	"os"
)

const defaultRoleName = "identity"

// GetIAMRoleName returns the IAM role name to use, from env var or default
func GetIAMRoleName() string {
	if roleName := os.Getenv("IAM_ROLE_NAME"); roleName != "" {
		return roleName
	}
	return defaultRoleName
}

func FormatRole(user IAM) (role string) {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", user.Account, GetIAMRoleName())
}
